"""Apply complete review decisions to verified G5 lineage without decoding payloads again."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import cast

from amyntor.data.incidents import peak_working_set, read_json, sha
from amyntor.data.leakage import implementation_hashes, preflight, retain
from amyntor.data.leakage_contract import (
    AuditLimit,
    LeakageError,
    load_audit_config,
    regular,
    verify_inputs,
)
from amyntor.data.leakage_graph import (
    Budget,
    close_store,
    open_store,
    shared_alert_graph,
    summarize_components,
)
from amyntor.data.leakage_pairs import apply_reviews, load_reviews
from amyntor.data.schema_contract import fingerprint


def finalize_reviews(
    g3: Path,
    g4: Path,
    lock: Path,
    schema: Path,
    manifest: Path,
    config_path: Path,
    scratch: Path,
    output: Path,
    prior_report: Path,
    prior_sha256: str,
    reviews: Path,
) -> dict[str, object]:
    """Cumulative review file only; never promote partial work or changed registry."""
    regular(prior_report)
    if sha(prior_report) != prior_sha256:
        raise LeakageError("Trusted prior G5 report SHA-256 required")
    prior = read_json(prior_report)
    if prior.get("result_sha256") != fingerprint(
        {
            k: prior[k]
            for k in (
                "audit_identity",
                "checks",
                "statistics",
                "status",
                "review_decisions_sha256",
            )
        }
    ):
        raise LeakageError("Prior G5 deterministic result identity mismatch")
    config = load_audit_config(config_path)
    expected_identity = fingerprint(
        {
            "config": config.sha256,
            "g4": config.document["g4"],
            "code": implementation_hashes(),
            "benchmark_modulus": None,
        }
    )
    checks = cast(dict[str, bool], prior["checks"])
    if (
        prior.get("gate") != "G5"
        or prior.get("training_allowed") is not False
        or prior.get("completed_work") is not True
        or prior.get("benchmark_modulus") is not None
        or prior.get("audit_identity") != expected_identity
        or not all(
            checks.get(k) is True
            for k in (
                "input_identity_verified",
                "complete_declared_scope",
                "row_accounting",
                "retained_memberships_reconciled",
                "component_accounting",
                "hard_edges_internal",
                "inputs_unchanged",
                "protected_artifacts_retained",
            )
        )
    ):
        raise LeakageError(
            "Only complete unchanged full-scope G5 lineage can be reviewed"
        )
    lineage = prior_report.parent / "lineage.sqlite3"
    regular(lineage)
    stored = cast(dict[str, dict[str, object]], prior["artifacts"])["lineage.sqlite3"]
    if lineage.stat().st_size != stored["bytes"] or sha(lineage) != stored["sha256"]:
        raise LeakageError("Prior protected lineage identity mismatch")
    planning = preflight(g3, g4, lock, schema, manifest, config_path, scratch, output)
    if not planning["feasible"]:
        raise AuditLimit("review_preflight")
    scratch.mkdir(parents=True)
    output.mkdir(parents=True)
    started = time.monotonic()
    budget = Budget(scratch, config.limits)
    before = {
        p: (p.stat().st_size, p.stat().st_mtime_ns, p.stat().st_ino)
        for p in (
            g3 / "incidents.sqlite3",
            g3 / "report.json",
            g4,
            lineage,
            prior_report,
        )
    }
    verify_inputs(g3, g4, lock, schema, manifest, config, scratch)
    connection, old_temp = open_store(scratch, g3, budget)
    result = dict(prior)
    result.pop("artifacts", None)
    statistics = dict(cast(dict[str, object], prior["statistics"]))
    result.update(
        {
            "status": "INCOMPLETE",
            "failure": None,
            "completed_work": False,
            "review_parent_report_sha256": prior_sha256,
            "payload_pass_reused": True,
        }
    )
    checks = dict(checks)
    checks["protected_artifacts_retained"] = False
    checks["required_review_resolved"] = False
    failed: str | None = None
    try:
        connection.execute(
            "ATTACH DATABASE ? AS previous", (lineage.resolve().as_uri() + "?mode=ro",)
        )
        if connection.execute(
            "SELECT audit_identity FROM previous.identity"
        ).fetchone() != (expected_identity,):
            raise LeakageError("Protected lineage header mismatch")
        connection.execute("INSERT INTO nodes SELECT * FROM previous.nodes")
        connection.execute("INSERT INTO sources SELECT * FROM previous.sources")
        connection.execute("UPDATE nodes SET p_all=id,p_retained=id")
        connection.execute("INSERT INTO pairs SELECT * FROM previous.pairs")
        connection.execute("UPDATE pairs SET decision=NULL")
        connection.execute("INSERT INTO findings SELECT * FROM previous.findings")
        connection.execute("UPDATE findings SET resolution=NULL,evidence=NULL")
        for table in (
            "contingencies",
            "value_associations",
            "count_associations",
            "downstream_associations",
            "alert_missingness",
            "downstream_context",
            "organization_classes",
        ):
            connection.execute(
                f"CREATE TABLE {table} AS SELECT * FROM previous.{table}"
            )
        connection.commit()
        statistics["shared_alert_graph"] = shared_alert_graph(connection, budget)
        load_reviews(connection, reviews, expected_identity, config, budget)
        statistics["review"] = review = apply_reviews(connection, budget)
        statistics.update(summarize_components(connection, budget))
        checks["required_review_resolved"] = (
            review["unresolved_pairs"] == review["unresolved_findings"] == 0
        )
        checks["component_accounting"] = (
            connection.execute(
                "SELECT COUNT(*) FROM nodes n JOIN component_ids c ON c.root=n.p_all"
            ).fetchone()[0]
            == statistics["full_context_incidents"]
        )
        checks["hard_edges_internal"] = (
            connection.execute(
                "SELECT COUNT(*) FROM edges e JOIN nodes a ON a.id=e.a JOIN nodes b ON b.id=e.b WHERE a.p_all<>b.p_all"
            ).fetchone()[0]
            == 0
        )
        result["artifacts"] = retain(
            connection, output, expected_identity, budget, config.document
        )
        checks["protected_artifacts_retained"] = True
        result["completed_work"] = True
    except AuditLimit as error:
        failed = str(error)
    except sqlite3.Error as error:
        failed = budget.failure or (
            "sqlite_storage_limit"
            if getattr(error, "sqlite_errorcode", None) == sqlite3.SQLITE_FULL
            else "sqlite_review_failure"
        )
    finally:
        close_store(connection, old_temp)
    checks["inputs_unchanged"] = all(
        before[p] == (p.stat().st_size, p.stat().st_mtime_ns, p.stat().st_ino)
        for p in before
    )
    result.update(
        {
            "checks": checks,
            "statistics": statistics,
            "status": "INCOMPLETE"
            if failed
            else ("PASSED" if all(checks.values()) else "BLOCKED"),
            "failure": failed
            or (None if all(checks.values()) else "unresolved_clearance_checks"),
            "source_verified": True,
            "independent_g4_saved_output_verified_this_invocation": True,
            "review_decisions_sha256": sha(reviews),
            "duration_seconds": round(time.monotonic() - started, 6),
            "peak_memory": peak_working_set(),
            "maximum_visible_scratch_bytes_lower_bound": budget.maximum_visible_bytes,
            "scratch_database_bytes": (scratch / "audit.sqlite3").stat().st_size,
            "phase_seconds": {"review_only": round(time.monotonic() - started, 6)},
            "last_phase": "review_only",
            "blocking_checks": sorted(
                name for name, passed in checks.items() if not passed
            ),
            "lineage_accepted": failed is None and all(checks.values()),
        }
    )
    result["result_sha256"] = fingerprint(
        {
            k: result[k]
            for k in (
                "audit_identity",
                "checks",
                "statistics",
                "status",
                "review_decisions_sha256",
            )
        }
    )
    return result
