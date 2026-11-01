"""One bounded payload pass and aggregate-only G5 provenance diagnostics."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections import Counter
from pathlib import Path
from typing import cast

from amyntor.data.leakage_contract import AuditConfig, AuditLimit, LeakageError
from amyntor.data.leakage_graph import Budget, union
from amyntor.data.leakage_pairs import identifier_token
from amyntor.data.provenance import Provenance
from amyntor.data.schema_contract import fingerprint, load_contract
from amyntor.features.incident_snapshot import accepted_values

OUTCOMES = (
    "ActionGrouped",
    "ActionGranular",
    "EvidenceRole",
    "Roles",
    "SuspicionLevel",
    "LastVerdict",
    "ThreatFamily",
)


def ingest(
    connection: sqlite3.Connection,
    config: AuditConfig,
    contract: Provenance,
    schema_path: Path,
    columns: list[str],
    budget: Budget,
) -> dict[str, object]:
    lexical = load_contract(schema_path)
    positions = {
        name: columns.index(name)
        for name in (
            *[r.field for r in config.identifiers],
            *contract.categorical,
            *OUTCOMES,
        )
    }
    coverage: dict[str, Counter[str]] = {
        r.field: Counter(
            {
                k: 0
                for k in (
                    "rows",
                    "empty_rows",
                    "verified_sentinel_rows",
                    "nonempty_non_sentinel_rows",
                    "eligible_rows",
                    "ambiguous_rows",
                    "unresolved_provenance_rows",
                )
            }
        )
        for r in config.identifiers
    }
    batches: dict[str, list[tuple[object, ...]]] = {
        k: [] for k in ("tokens", "features", "outcomes", "sources")
    }
    sql = {
        "tokens": "INSERT OR IGNORE INTO tokens VALUES (?,?,?,?,?)",
        "features": "INSERT OR IGNORE INTO features VALUES (?,?,?,?,?,?,?)",
        "outcomes": "INSERT OR IGNORE INTO outcomes VALUES (?,?,?,?)",
        "sources": "INSERT OR IGNORE INTO sources VALUES (?,?)",
    }
    batch_size = batch_bytes = rows = 0

    def flush() -> None:
        nonlocal batch_size, batch_bytes
        budget.check()
        for table, batch in batches.items():
            connection.executemany(sql[table], batch)
            batch.clear()
        connection.commit()
        batch_size = batch_bytes = 0

    def append(table: str, record: tuple[object, ...]) -> None:
        nonlocal batch_size, batch_bytes
        cost = 256 + sum(
            len(v) * 2 if isinstance(v, (str, bytes)) else 32 for v in record
        )
        if cost > config.limits.batch_bytes:
            raise AuditLimit("single_audit_record_budget")
        if (
            batch_size >= config.limits.batch_rows
            or batch_bytes + cost > config.limits.batch_bytes
        ):
            flush()
        batches[table].append(record)
        batch_size += 1
        batch_bytes += cost

    for node, org, alert, source, payload in connection.execute(
        "SELECT n.id,n.org,e.alert,e.source,e.payload FROM nodes n "
        "CROSS JOIN src.evidence e INDEXED BY evidence_incident "
        "WHERE n.org=e.org AND n.incident=e.incident"
    ):
        budget.check()
        if len(payload) > config.limits.payload_chars:
            raise AuditLimit("payload_limit")
        decoded: object = json.loads(payload)
        if (
            not isinstance(decoded, list)
            or len(cast(list[object], decoded)) != len(columns)
            or any(not isinstance(v, str) for v in cast(list[object], decoded))
        ):
            raise LeakageError("G3 payload incompatible with accepted schema")
        cells = cast(list[str], decoded)
        if source not in {f.name for f in lexical.files}:
            raise LeakageError("Unrecognized original source partition")
        append("sources", (node, source))
        for rule in config.identifiers:
            value = cells[positions[rule.field]]
            if len(value) > config.limits.field_chars:
                raise AuditLimit("identifier_field_limit")
            count = coverage[rule.field]
            count["rows"] += 1
            count["empty_rows"] += int(not value)
            count["verified_sentinel_rows"] += int(
                bool(value) and value in rule.verified_sentinels
            )
            token = identifier_token(rule, org, value)
            if token is not None:
                digest, eligible, ambiguous = token
                append(
                    "tokens", (node, rule.field, digest, int(eligible), int(ambiguous))
                )
                count["nonempty_non_sentinel_rows"] += 1
                count["eligible_rows"] += int(eligible)
                count["ambiguous_rows"] += int(ambiguous)
                count["unresolved_provenance_rows"] += int(rule.status == "UNRESOLVED")
        values = {n: cells[positions[n]] for n in contract.categorical}
        for field, value in accepted_values(
            values, contract, config.limits.field_chars
        ):
            append(
                "features",
                (
                    node,
                    alert,
                    field,
                    hashlib.sha256(value.encode()).digest(),
                    int(not value),
                    int(value in lexical.null_tokens),
                    int(value in lexical.sentinel_tokens),
                ),
            )
        for field in OUTCOMES:
            value = cells[positions[field]]
            if len(value) > config.limits.field_chars:
                raise AuditLimit("outcome_diagnostic_field_limit")
            append(
                "outcomes",
                (node, field, hashlib.sha256(value.encode()).digest(), int(not value)),
            )
        rows += 1
    flush()
    return {
        "evidence_rows_decoded": rows,
        "identifier_coverage": {k: dict(v) for k, v in coverage.items()},
    }


def relationship_statistics(connection: sqlite3.Connection) -> dict[str, object]:
    duplicates: dict[str, object] = {}
    for retained, name in ((0, "quarantined"), (1, "retained")):
        total, unique = connection.execute(
            "SELECT COUNT(*),COUNT(DISTINCT e.exact) FROM src.evidence e JOIN nodes n "
            "ON n.org=e.org AND n.incident=e.incident WHERE n.retained=?",
            (retained,),
        ).fetchone()
        duplicates[name] = {
            "input_rows": total,
            "exact_unique_rows": unique,
            "repeated_occurrences": total - unique,
        }
    cross_source = connection.execute(
        "SELECT COUNT(*) FROM (SELECT e.exact FROM src.evidence e JOIN nodes n "
        "ON n.org=e.org AND n.incident=e.incident GROUP BY e.exact HAVING COUNT(DISTINCT e.source)>1)"
    ).fetchone()[0]
    connection.execute(
        "CREATE TABLE source_counts AS SELECT node,COUNT(*) AS sources,"
        "GROUP_CONCAT(source,'|') AS signature FROM (SELECT * FROM sources ORDER BY node,source) GROUP BY node"
    )
    source_counts = {
        "retained_single_source": 0,
        "retained_cross_source": 0,
        "quarantined_single_source": 0,
        "quarantined_cross_source": 0,
    }
    for retained, count, total in connection.execute(
        "SELECT n.retained,s.sources,COUNT(*) FROM nodes n JOIN source_counts s ON s.node=n.id GROUP BY n.retained,s.sources"
    ):
        source_counts[
            ("retained" if retained else "quarantined")
            + ("_cross_source" if count > 1 else "_single_source")
        ] += total
    connection.executescript("""
        CREATE TABLE alert_sources AS SELECT DISTINCT e.org,e.alert,e.source
          FROM nodes n CROSS JOIN src.evidence e INDEXED BY evidence_incident
          WHERE n.org=e.org AND n.incident=e.incident;
        CREATE INDEX alert_source_keys ON alert_sources(org,alert);
        CREATE TABLE alert_audit AS SELECT m.org,m.alert,COUNT(*) AS degree,
          SUM(n.retained) AS retained_degree FROM src.incident_alerts m JOIN nodes n
          ON n.org=m.org AND n.incident=m.incident GROUP BY m.org,m.alert;
        CREATE TABLE organization_audit AS SELECT org,COUNT(*) AS incidents,
          SUM(retained) AS retained FROM nodes GROUP BY org;
    """)
    shared = connection.execute(
        "SELECT COALESCE(SUM(degree>1 AND retained_degree>=2),0),"
        "COALESCE(SUM(retained_degree>0 AND retained_degree<degree),0),COALESCE(MAX(degree),0) FROM alert_audit"
    ).fetchone()
    degree_bins = {
        str(label): count
        for label, count in connection.execute(
            "SELECT CASE WHEN degree=1 THEN '1' WHEN degree=2 THEN '2' WHEN degree<=5 THEN '3-5' "
            "WHEN degree<=10 THEN '6-10' WHEN degree<=25 THEN '11-25' WHEN degree<=100 THEN '26-100' ELSE '>100' END,"
            "COUNT(*) FROM alert_audit GROUP BY 1"
        )
    }
    return {
        "scoped_alert_incident_degree_bins": degree_bins,
        "exact_duplicates": duplicates,
        "cross_source_exact_hash_groups": cross_source,
        "incident_source_counts": source_counts,
        "shared_alerts_retained_to_retained": shared[0],
        "shared_alerts_retained_to_quarantined": shared[1],
        "maximum_alert_incident_degree": shared[2],
        "cross_incident_cross_source_scoped_alerts": connection.execute(
            "SELECT COUNT(*) FROM (SELECT a.org,a.alert FROM alert_audit a JOIN alert_sources s USING(org,alert) "
            "WHERE a.degree>1 GROUP BY a.org,a.alert HAVING COUNT(DISTINCT s.source)>1)"
        ).fetchone()[0],
        "content_hash_groups_with_different_known_grades": connection.execute(
            "SELECT COUNT(*) FROM (SELECT e.content FROM nodes n CROSS JOIN src.evidence e INDEXED BY evidence_incident "
            "WHERE n.org=e.org AND n.incident=e.incident AND e.grade IN ('TruePositive','FalsePositive','BenignPositive') "
            "GROUP BY e.content HAVING COUNT(DISTINCT e.grade)>1)"
        ).fetchone()[0],
        "organizations": connection.execute(
            "SELECT COUNT(*) FROM organization_audit"
        ).fetchone()[0],
        "largest_organization_incidents": connection.execute(
            "SELECT COALESCE(MAX(incidents),0) FROM organization_audit"
        ).fetchone()[0],
        "source_partition_authority": "diagnostic_only_not_evaluation_roles",
    }


def finding(
    connection: sqlite3.Connection, kind: str, scope: str, support: int, detail: str
) -> None:
    identity = fingerprint(["guide-g5-finding-v1", kind, scope, detail])
    connection.execute(
        "INSERT OR IGNORE INTO findings VALUES (?,?,?,?,?,NULL,NULL)",
        (identity, kind, scope, support, detail),
    )


def diagnostics(
    connection: sqlite3.Connection, config: AuditConfig, budget: Budget
) -> dict[str, object]:
    connection.executescript("""
        CREATE TABLE facts AS SELECT n.id AS node,n.org,n.grade,s.sources,s.signature,
          CASE WHEN n.alerts=1 THEN '1' WHEN n.alerts=2 THEN '2' WHEN n.alerts<=5 THEN '3-5'
          WHEN n.alerts<=10 THEN '6-10' WHEN n.alerts<=25 THEN '11-25'
          WHEN n.alerts<=100 THEN '26-100' ELSE '>100' END AS count_bin
          FROM nodes n JOIN source_counts s ON s.node=n.id WHERE n.retained=1;
        CREATE UNIQUE INDEX fact_keys ON facts(node);
        CREATE TABLE feature_incident AS SELECT f.node,f.field,MAX(empty) AS empty,
          MAX(null_like) AS null_like,MAX(sentinel) AS sentinel FROM features f
          JOIN facts x USING(node) GROUP BY f.node,f.field;
        CREATE TABLE association AS SELECT x.node,x.org,x.grade,x.sources,x.signature,f.field,
          f.empty,f.null_like,f.sentinel FROM facts x JOIN feature_incident f USING(node);
        CREATE TABLE contingencies(scope TEXT,stratum TEXT,field TEXT,measure TEXT,grade TEXT,
          support INTEGER,affected INTEGER);
    """)
    for scope, expression in (
        ("overall", "'all'"),
        ("organization", "org"),
        ("source_membership", "signature"),
        ("organization_source", "org || ':' || signature"),
    ):
        for measure in ("empty", "null_like", "sentinel"):
            budget.check()
            connection.execute(
                f"INSERT INTO contingencies SELECT ?,{expression},field,?,grade,COUNT(*),SUM({measure}) "
                f"FROM association GROUP BY {expression},field,grade",
                (scope, measure),
            )
    connection.execute(
        "CREATE INDEX contingency_keys ON contingencies(scope,stratum,field,measure)"
    )
    for (
        scope,
        stratum,
        field,
        measure,
        minimum,
        maximum,
        minimum_support,
        support,
        classes,
    ) in connection.execute(
        "SELECT scope,stratum,field,measure,MIN(1.0*affected/support),MAX(1.0*affected/support),"
        "MIN(support),SUM(support),COUNT(*) FROM contingencies GROUP BY scope,stratum,field,measure"
    ):
        budget.check()
        scope_id = fingerprint([scope, stratum])
        if classes < 3 or minimum_support < cast(
            int, config.rules["minimum_comparison_support"]
        ):
            finding(
                connection,
                "insufficient_stratum_support",
                scope_id,
                support,
                f"{field}:{measure}:sparse_or_single_class",
            )
        elif maximum - minimum >= cast(float, config.rules["missingness_gap"]):
            finding(
                connection,
                "missingness_association",
                scope_id,
                support,
                f"{field}:{measure}:gap_at_least_0.10",
            )
    # Categorical context and count distributions are diagnostic-only; no fitted
    # vocabulary or encoder. Hash values stay in private scratch, not public JSON.
    connection.executescript("""
        CREATE TABLE feature_alert AS SELECT f.node,f.alert,f.field,MAX(empty) AS empty,
          MAX(null_like) AS null_like,MAX(sentinel) AS sentinel FROM features f
          JOIN facts x USING(node) GROUP BY f.node,f.alert,f.field;
        CREATE TABLE alert_missingness AS SELECT f.field,x.grade,COUNT(*) AS alerts,
          SUM(f.empty) AS empty_alerts,SUM(f.null_like) AS null_like_alerts,
          SUM(f.sentinel) AS sentinel_alerts FROM feature_alert f JOIN facts x USING(node)
          GROUP BY f.field,x.grade;
        CREATE TABLE organization_classes AS SELECT org,grade,COUNT(*) AS incidents
          FROM facts GROUP BY org,grade;
        CREATE TABLE feature_values AS SELECT DISTINCT f.node,f.field,f.value FROM features f JOIN facts x USING(node);
        CREATE TABLE value_associations AS SELECT v.field,v.value,x.grade,COUNT(*) AS incidents
          FROM feature_values v JOIN facts x USING(node) GROUP BY v.field,v.value,x.grade;
        CREATE TABLE count_associations AS SELECT count_bin,grade,COUNT(*) AS incidents
          FROM facts GROUP BY count_bin,grade;
        CREATE TABLE outcome_presence AS SELECT node,field,MAX(empty=0) AS present FROM outcomes GROUP BY node,field;
        CREATE TABLE downstream_associations AS SELECT o.field,o.present,x.count_bin,x.grade,
          COUNT(*) AS incidents FROM outcome_presence o JOIN facts x USING(node)
          GROUP BY o.field,o.present,x.count_bin,x.grade;
        CREATE TABLE downstream_context AS SELECT v.field AS context_field,v.value,
          o.field AS outcome_field,o.present,x.grade,COUNT(*) AS incidents
          FROM feature_values v JOIN facts x USING(node) JOIN outcome_presence o USING(node)
          GROUP BY v.field,v.value,o.field,o.present,x.grade;
    """)
    for field, value, support in connection.execute(
        "SELECT field,value,SUM(incidents) FROM value_associations GROUP BY field,value HAVING COUNT(*)=1"
    ):
        finding(
            connection,
            "deterministic_context_class_association",
            fingerprint([field, bytes(value).hex()]),
            support,
            "Association_requires_mechanism_review_not_automatic_leakage",
        )
    for count_bin, support in connection.execute(
        "SELECT count_bin,SUM(incidents) FROM count_associations GROUP BY count_bin HAVING COUNT(*)=1"
    ):
        finding(
            connection,
            "deterministic_count_class_association",
            fingerprint([count_bin]),
            support,
            "Snapshot_membership_lineage_review_required",
        )
    for field, present, support in connection.execute(
        "SELECT field,present,SUM(incidents) FROM downstream_associations GROUP BY field,present HAVING COUNT(DISTINCT grade)=1"
    ):
        finding(
            connection,
            "downstream_outcome_association",
            fingerprint([field, present]),
            support,
            "Excluded_outcome_diagnostic_only_review_context_and_membership_lineage",
        )
    finding(
        connection,
        "snapshot_membership_lineage",
        "retrospective_only",
        connection.execute("SELECT COUNT(*) FROM facts").fetchone()[0],
        "Point_in_time_unproven_membership_can_reflect_investigation_requires_explicit_review",
    )
    entity: dict[str, object] = {}
    for rule in config.identifiers[1:]:
        count, ambiguous, eligible = connection.execute(
            "SELECT COUNT(*),COALESCE(SUM(ambiguous),0),COALESCE(SUM(eligible),0) FROM tokens WHERE field=?",
            (rule.field,),
        ).fetchone()
        reused = connection.execute(
            "SELECT COUNT(*) FROM (SELECT token FROM tokens WHERE field=? GROUP BY token HAVING COUNT(*)>1)",
            (rule.field,),
        ).fetchone()[0]
        cross_org = connection.execute(
            "SELECT COUNT(*) FROM (SELECT t.token FROM tokens t JOIN nodes n ON n.id=t.node WHERE field=? GROUP BY token HAVING COUNT(DISTINCT n.org)>1)",
            (rule.field,),
        ).fetchone()[0]
        entity[rule.field] = {
            "incident_token_memberships": count,
            "ambiguous_memberships": ambiguous,
            "copy_eligible_memberships": eligible,
            "reused_code_groups": reused,
            "cross_organization_code_groups_not_identity_proof": cross_org,
            "scope": rule.scope,
            "status": rule.status,
        }
    connection.commit()
    return {
        "entity_diagnostics": entity,
        "finding_count": connection.execute("SELECT COUNT(*) FROM findings").fetchone()[
            0
        ],
        "contingency_cells": connection.execute(
            "SELECT COUNT(*) FROM contingencies"
        ).fetchone()[0],
        "label_denominator": "retained_incidents_not_evidence_rows",
        "private_tables": [
            "contingencies",
            "value_associations",
            "count_associations",
            "downstream_associations",
            "alert_missingness",
            "downstream_context",
            "organization_classes",
        ],
    }


def sensitivity_graph(connection: sqlite3.Connection, budget: Budget) -> None:
    """Counterfactual code equality bound, never a confirmed hard edge."""
    previous: tuple[str, bytes] | None = None
    first = 0
    for field, token, node in connection.execute(
        "SELECT field,token,node FROM tokens WHERE field<>'AlertId' ORDER BY field,token,node"
    ):
        budget.check()
        if previous != (field, token):
            previous, first = (field, token), node
        elif node != first:
            union(connection, first, node, "p_sensitivity", budget)
    connection.commit()
