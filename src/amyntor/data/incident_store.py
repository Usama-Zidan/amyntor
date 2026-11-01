"""Disk-backed G3 accounting. SQLite is an offline artifact, not a service."""

from __future__ import annotations

import hashlib
import json
import math
import sqlite3
from collections.abc import Callable
from typing import cast

REASONS = {
    1: "missing_grade",
    2: "conflicting_known_grades",
    4: "unknown_grade",
    8: "conflicting_alert_metadata",
}

DDL = """
CREATE TABLE evidence (
    row_id INTEGER PRIMARY KEY, org TEXT NOT NULL, incident TEXT NOT NULL,
    alert TEXT NOT NULL, grade TEXT NOT NULL, grade_state INTEGER NOT NULL, source TEXT NOT NULL,
    usage TEXT NOT NULL, exact BLOB NOT NULL, content BLOB NOT NULL,
    invariant BLOB NOT NULL, payload TEXT NOT NULL
);
"""

# Every source row survives in evidence; records is the multiplicity-preserving
# exact-deduplicated projection. Representatives have identical canonical payloads.
STATEMENTS = (
    ("exact index", "CREATE INDEX evidence_exact ON evidence(exact,source,usage)"),
    (
        "exact records",
        """CREATE TABLE records AS SELECT exact, MIN(row_id) AS representative,
        COUNT(*) AS multiplicity FROM evidence GROUP BY exact""",
    ),
    ("record index", "CREATE UNIQUE INDEX records_exact ON records(exact)"),
    (
        "incident index",
        "CREATE INDEX evidence_incident ON evidence(org,incident,alert,grade,grade_state,source,exact)",
    ),
    (
        "incident summaries",
        """CREATE TABLE incidents AS SELECT org,incident,COUNT(*) AS input_rows,
        COUNT(DISTINCT exact) AS unique_rows,COUNT(DISTINCT alert) AS alerts,
        COUNT(DISTINCT CASE WHEN grade IN
          ('TruePositive','BenignPositive','FalsePositive') THEN grade END) AS known_grades,
        MIN(CASE WHEN grade IN ('TruePositive','BenignPositive','FalsePositive')
          THEN grade END) AS grade,
        SUM(grade_state=0) AS missing_rows,
        SUM(grade_state=4) AS unknown_rows,
        COUNT(DISTINCT source) AS source_count, 0 AS reason_mask
        FROM evidence GROUP BY org,incident""",
    ),
    (
        "incident keys",
        "CREATE UNIQUE INDEX incident_keys ON incidents(org,incident)",
    ),
    (
        "alert membership",
        "CREATE TABLE incident_alerts AS SELECT DISTINCT org,incident,alert FROM evidence",
    ),
    (
        "membership index",
        "CREATE UNIQUE INDEX membership_alert ON incident_alerts(org,alert,incident)",
    ),
    (
        "alert index",
        "CREATE INDEX evidence_alert ON evidence(org,alert,incident,invariant)",
    ),
    (
        "alert summaries",
        """CREATE TABLE alerts AS SELECT org,alert,COUNT(DISTINCT incident) AS incidents,
        COUNT(DISTINCT invariant) AS invariant_versions FROM evidence GROUP BY org,alert""",
    ),
    ("alert keys", "CREATE UNIQUE INDEX alert_keys ON alerts(org,alert)"),
    (
        "conflicting memberships",
        """CREATE TABLE alert_conflicts AS SELECT DISTINCT m.org,m.incident
        FROM incident_alerts m JOIN alerts a USING(org,alert) WHERE a.invariant_versions>1""",
    ),
    (
        "conflict index",
        "CREATE UNIQUE INDEX conflict_keys ON alert_conflicts(org,incident)",
    ),
    (
        "quarantine",
        """UPDATE incidents SET reason_mask=(missing_rows>0)*1+(known_grades>1)*2+
        (unknown_rows>0)*4+8*EXISTS(SELECT 1 FROM alert_conflicts c
        WHERE c.org=incidents.org AND c.incident=incidents.incident)""",
    ),
    (
        "evidence content index",
        "CREATE INDEX evidence_content ON evidence(content,grade)",
    ),
)


def scalar(connection: sqlite3.Connection, query: str) -> int:
    row = connection.execute(query).fetchone()
    return int(row[0] or 0)


def distribution(connection: sqlite3.Connection, column: str) -> dict[str, int | float]:
    if column not in {"input_rows", "unique_rows", "alerts"}:
        raise ValueError("Unsupported incident statistic")
    size = scalar(connection, "SELECT COUNT(*) FROM incidents")
    if not size:
        return {"min": 0, "median": 0, "p95": 0, "max": 0}
    # SQL sorts spill to disk; fetch just the two middle values and nearest-rank p95.
    middle = connection.execute(
        f"SELECT {column} FROM incidents ORDER BY {column} LIMIT 2 OFFSET ?",
        ((size - 1) // 2,),
    ).fetchall()
    median = float(middle[0][0])
    if size % 2 == 0:
        median = (median + int(middle[1][0])) / 2
    p95 = connection.execute(
        f"SELECT {column} FROM incidents ORDER BY {column} LIMIT 1 OFFSET ?",
        (math.ceil(size * 0.95) - 1,),
    ).fetchone()[0]
    bounds = connection.execute(
        f"SELECT MIN({column}),MAX({column}) FROM incidents"
    ).fetchone()
    return {
        "min": int(bounds[0]),
        "median": median,
        "p95": int(p95),
        "max": int(bounds[1]),
    }


def summarize(
    connection: sqlite3.Connection,
    progress: Callable[[str], None],
    *,
    incident_scoped: bool = False,
) -> dict[str, object]:
    for name, sql in STATEMENTS:
        if incident_scoped and name == "alert summaries":
            # Global variations/reuse remain diagnostic, never a v2 quarantine rule.
            sql = """CREATE TABLE alerts AS SELECT org,alert,
                COUNT(DISTINCT incident) AS incidents,
                COUNT(DISTINCT invariant) AS invariant_versions,
                COUNT(DISTINCT source) AS source_count
                FROM evidence GROUP BY org,alert"""
        if incident_scoped and name == "conflicting memberships":
            progress("incident-scoped alert metadata")
            connection.execute("""CREATE TABLE incident_alert_metadata AS SELECT
                org,incident,alert,COUNT(DISTINCT invariant) AS invariant_versions,
                COUNT(DISTINCT source) AS source_count,COUNT(*) AS input_rows
                FROM evidence GROUP BY org,alert,incident""")
            connection.execute("""CREATE UNIQUE INDEX incident_alert_metadata_keys
                ON incident_alert_metadata(org,incident,alert)""")
            connection.commit()
            sql = """CREATE TABLE alert_conflicts AS SELECT DISTINCT org,incident
                FROM incident_alert_metadata WHERE invariant_versions>1"""
        progress(name)
        connection.execute(sql)
        connection.commit()
    collisions = scalar(
        connection,
        """SELECT COUNT(*) FROM records r JOIN evidence e USING(exact)
        JOIN evidence first ON first.row_id=r.representative
        WHERE r.multiplicity>1 AND e.payload<>first.payload""",
    )
    total = scalar(connection, "SELECT COUNT(*) FROM evidence")
    unique = scalar(connection, "SELECT COUNT(*) FROM records")
    incident_count = scalar(connection, "SELECT COUNT(*) FROM incidents")
    reasons: dict[str, object] = {}
    for bit, name in REASONS.items():
        row = connection.execute(
            "SELECT COUNT(*),COALESCE(SUM(input_rows),0) FROM incidents WHERE reason_mask & ? <> 0",
            (bit,),
        ).fetchone()
        reasons[name] = {"incidents": row[0], "input_rows": row[1]}
    combinations = [
        {"reason_mask": row[0], "incidents": row[1], "input_rows": row[2]}
        for row in connection.execute(
            "SELECT reason_mask,COUNT(*),SUM(input_rows) FROM incidents GROUP BY reason_mask ORDER BY reason_mask"
        )
    ]
    retained_rows = scalar(
        connection, "SELECT SUM(input_rows) FROM incidents WHERE reason_mask=0"
    )
    quarantined_rows = scalar(
        connection, "SELECT SUM(input_rows) FROM incidents WHERE reason_mask<>0"
    )
    retained_unique = scalar(
        connection, "SELECT SUM(unique_rows) FROM incidents WHERE reason_mask=0"
    )
    quarantined_unique = scalar(
        connection, "SELECT SUM(unique_rows) FROM incidents WHERE reason_mask<>0"
    )
    logical_evidence = scalar(
        connection,
        "SELECT COUNT(*) FROM (SELECT 1 FROM evidence GROUP BY content,grade)",
    )
    progress("logical digest")
    digest = hashlib.sha256()
    for exact, source, usage, count in connection.execute(
        "SELECT exact,source,usage,COUNT(*) FROM evidence GROUP BY exact,source,usage ORDER BY exact,source,usage"
    ):
        digest.update(
            json.dumps(
                [cast(bytes, exact).hex(), source, usage, count],
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode()
            + b"\n"
        )
    checks = {
        "canonical_hash_collisions_absent": collisions == 0,
        "input_rows_reconciled": retained_rows + quarantined_rows == total,
        "unique_rows_reconciled": retained_unique + quarantined_unique == unique,
        "duplicate_multiplicities_reconciled": scalar(
            connection, "SELECT SUM(multiplicity) FROM records"
        )
        == total,
        "incidents_reconciled": sum(int(c["incidents"]) for c in combinations)
        == incident_count,
        "retained_labels_consistent": scalar(
            connection,
            "SELECT COUNT(*) FROM incidents WHERE reason_mask=0 AND (known_grades<>1 OR missing_rows<>0 OR unknown_rows<>0 OR alerts=0)",
        )
        == 0,
    }
    diagnostics: dict[str, object] = {}
    if incident_scoped:
        checks["incident_alert_rows_reconciled"] = (
            scalar(connection, "SELECT SUM(input_rows) FROM incident_alert_metadata")
            == total
        )
        checks["retained_alert_metadata_consistent"] = (
            scalar(
                connection,
                """SELECT COUNT(*) FROM incident_alert_metadata m
            JOIN incidents i USING(org,incident)
            WHERE i.reason_mask=0 AND m.invariant_versions>1""",
            )
            == 0
        )
        diagnostics = {
            "metadata_consistency_scope": ["OrgId", "IncidentId", "AlertId"],
            "conflicting_incident_alerts": scalar(
                connection,
                "SELECT COUNT(*) FROM incident_alert_metadata WHERE invariant_versions>1",
            ),
            "unique_incident_alerts": scalar(
                connection, "SELECT COUNT(*) FROM incident_alert_metadata"
            ),
            "cross_source_scoped_alerts": scalar(
                connection, "SELECT COUNT(*) FROM alerts WHERE source_count>1"
            ),
            "cross_incident_cross_source_scoped_alerts": scalar(
                connection,
                "SELECT COUNT(*) FROM alerts WHERE incidents>1 AND source_count>1",
            ),
            "cross_source_incident_alerts": scalar(
                connection,
                "SELECT COUNT(*) FROM incident_alert_metadata WHERE source_count>1",
            ),
        }
    return {
        **diagnostics,
        "input_evidence_rows": total,
        "unique_incidents": incident_count,
        "unique_scoped_alerts": scalar(connection, "SELECT COUNT(*) FROM alerts"),
        "retained_labeled_incidents": scalar(
            connection, "SELECT COUNT(*) FROM incidents WHERE reason_mask=0"
        ),
        "quarantined_incidents": scalar(
            connection, "SELECT COUNT(*) FROM incidents WHERE reason_mask<>0"
        ),
        "quarantine_by_reason_overlapping": reasons,
        "quarantine_disjoint_reason_combinations": combinations,
        "retained_incident_labels": dict(
            connection.execute(
                "SELECT grade,COUNT(*) FROM incidents WHERE reason_mask=0 GROUP BY grade ORDER BY grade"
            )
        ),
        "exact_unique_rows": unique,
        "exact_duplicate_rows": total - unique,
        "repeated_evidence_rows_ignoring_row_id": total - logical_evidence,
        "nonexact_repeated_evidence_rows": unique - logical_evidence,
        "label_only_conflicting_evidence_groups": scalar(
            connection,
            "SELECT COUNT(*) FROM (SELECT 1 FROM evidence GROUP BY content HAVING COUNT(DISTINCT grade)>1)",
        ),
        "cross_source_incidents": scalar(
            connection, "SELECT COUNT(*) FROM incidents WHERE source_count>1"
        ),
        "cross_source_quarantined_incidents": scalar(
            connection,
            "SELECT COUNT(*) FROM incidents WHERE source_count>1 AND reason_mask<>0",
        ),
        "cross_source_exact_records": scalar(
            connection,
            "SELECT COUNT(*) FROM (SELECT 1 FROM evidence GROUP BY exact HAVING COUNT(DISTINCT source)>1)",
        ),
        "reused_scoped_alerts": scalar(
            connection, "SELECT COUNT(*) FROM alerts WHERE incidents>1"
        ),
        "conflicting_scoped_alerts": scalar(
            connection, "SELECT COUNT(*) FROM alerts WHERE invariant_versions>1"
        ),
        "evidence_rows_per_incident_before_dedup": distribution(
            connection, "input_rows"
        ),
        "evidence_rows_per_incident_after_dedup": distribution(
            connection, "unique_rows"
        ),
        "distinct_alerts_per_incident": distribution(connection, "alerts"),
        "row_reconciliation": {
            "retained_unique": retained_unique,
            "retained_duplicate_occurrences": retained_rows - retained_unique,
            "quarantined_unique": quarantined_unique,
            "quarantined_duplicate_occurrences": quarantined_rows - quarantined_unique,
            "orphan_or_unparseable_rows": 0,
            "unexplained_loss": total - retained_rows - quarantined_rows,
        },
        "checks": checks,
        "logical_records_sha256": digest.hexdigest(),
    }
