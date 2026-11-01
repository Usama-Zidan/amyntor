"""Portable, bounded G5 orchestration; no reconstruction, splits or model fitting."""

from __future__ import annotations

import hashlib
import json
import platform
import shutil
import sqlite3
import time
from collections.abc import Callable
from pathlib import Path
from typing import cast

from amyntor.data.incidents import peak_working_set, sha
from amyntor.data.leakage_contract import (
    AuditLimit,
    LeakageError,
    load_audit_config,
    verify_inputs,
)
from amyntor.data.leakage_diagnostics import (
    diagnostics,
    ingest,
    relationship_statistics,
    sensitivity_graph,
)
from amyntor.data.leakage_graph import (
    Budget,
    close_store,
    open_store,
    shared_alert_graph,
    summarize_components,
)
from amyntor.data.leakage_pairs import apply_reviews, find_pairs, load_reviews
from amyntor.data.schema_contract import fingerprint


def implementation_hashes() -> dict[str, str]:
    return {
        name: sha(Path(__file__).with_name(name))
        for name in (
            "leakage.py",
            "leakage_contract.py",
            "leakage_graph.py",
            "leakage_pairs.py",
            "leakage_diagnostics.py",
            "leakage_review.py",
            "audit_leakage.py",
        )
    }


def ancestor(path: Path) -> Path:
    current = path.resolve()
    while not current.exists():
        current = current.parent
    return current


def preflight(
    g3: Path,
    g4: Path,
    lock: Path,
    schema: Path,
    manifest: Path,
    config_path: Path,
    scratch: Path,
    output: Path,
    benchmark_modulus: int | None = None,
) -> dict[str, object]:
    config = load_audit_config(config_path)
    if benchmark_modulus is not None and (
        type(benchmark_modulus) is not int or benchmark_modulus < 2
    ):
        raise LeakageError(
            "Benchmark modulus must be >= 2; no full run disguised as benchmark"
        )
    if scratch.exists() or output.exists() or scratch.resolve() == output.resolve():
        raise LeakageError("Choose fresh distinct scratch and retained-output paths")
    for path in (scratch, output):
        if path.resolve().is_relative_to(g3.resolve()) or g4.resolve().is_relative_to(
            path.resolve()
        ):
            raise LeakageError("Outputs cannot contain or modify accepted inputs")
    if scratch.resolve().is_relative_to(
        output.resolve()
    ) or output.resolve().is_relative_to(scratch.resolve()):
        raise LeakageError("Separate disposable scratch from retained artifacts")
    _, r3, _ = verify_inputs(g3, g4, lock, schema, manifest, config, None)
    rows = cast(dict[str, int], r3["statistics"])["input_evidence_rows"]
    planning_rows = (rows + (benchmark_modulus or 1) - 1) // (benchmark_modulus or 1)
    # Narrow deduplicated token records plus indexes/sorts. This is deliberately
    # a planning assumption, not a measured bound on arbitrary entity cardinality.
    estimate = planning_rows * (64 + 96 * len(config.identifiers)) * 3
    scratch_fs, retained_fs = ancestor(scratch.parent), ancestor(output.parent)
    free, retained_free = (
        shutil.disk_usage(scratch_fs).free,
        shutil.disk_usage(retained_fs).free,
    )
    required_scratch = estimate + config.limits.minimum_free_bytes
    required_retained = config.limits.retained_bytes + config.limits.minimum_free_bytes
    same = scratch_fs.stat().st_dev == retained_fs.stat().st_dev
    feasible = (
        estimate <= config.limits.scratch_bytes
        and free >= required_scratch
        and retained_free >= required_retained
    )
    if same:
        feasible = feasible and free >= required_scratch + required_retained
    return {
        "gate": "G5",
        "status": "PREFLIGHT_ONLY",
        "training_allowed": False,
        "source_verified": False,
        "config_sha256": config.sha256,
        "benchmark_modulus": benchmark_modulus,
        "scratch_filesystem": str(scratch_fs),
        "retained_filesystem": str(retained_fs),
        "available_scratch_bytes": free,
        "available_retained_bytes": retained_free,
        "estimated_scratch_bytes": estimate,
        "estimate_basis": "rows*(64+96*registry_fields)*3; unmeasured index/sort factor",
        "retained_budget_bytes": config.limits.retained_bytes,
        "same_filesystem": same,
        "feasible": feasible,
    }


def retain(
    connection: sqlite3.Connection,
    output: Path,
    identity: str,
    budget: Budget,
    configuration: dict[str, object],
) -> dict[str, object]:
    """Narrow protected audit lineage; no full evidence/token database copy."""
    path = output / "lineage.sqlite3"
    connection.execute("ATTACH DATABASE ? AS retained", (str(path.resolve()),))
    page = connection.execute("PRAGMA retained.page_size").fetchone()[0]
    connection.execute(
        f"PRAGMA retained.max_page_count={max(1, budget.limits.retained_bytes // page)}"
    )
    for table in (
        "nodes",
        "sources",
        "edges",
        "pairs",
        "findings",
        "reviews",
        "component_ids",
        "contingencies",
        "value_associations",
        "count_associations",
        "downstream_associations",
        "alert_missingness",
        "downstream_context",
        "organization_classes",
        "component_composition",
        "component_sources",
    ):
        budget.check()
        # Nodes contain audit target metadata; review samples below never expose it.
        connection.execute(
            f"CREATE TABLE retained.{table} AS SELECT * FROM main.{table}"
        )
    connection.execute(
        "CREATE TABLE retained.incident_components AS SELECT n.org,n.incident,n.retained,c.digest AS component_sha256 FROM nodes n JOIN component_ids c ON c.root=n.p_all"
    )
    connection.execute(
        "CREATE UNIQUE INDEX retained.incident_component_key ON incident_components(org,incident)"
    )
    connection.execute(
        "CREATE TABLE retained.identity(contract_version TEXT,audit_identity TEXT,component_scope TEXT,training_allowed INTEGER)"
    )
    connection.execute(
        "INSERT INTO retained.identity VALUES ('guide-v1-leakage-lineage-1',?,'hard_edges_with_quarantine_bridges',0)",
        (identity,),
    )
    connection.commit()
    connection.execute("DETACH DATABASE retained")
    if (
        path.stat().st_size > budget.limits.retained_bytes
        or shutil.disk_usage(output).free < budget.limits.minimum_free_bytes
    ):
        raise AuditLimit("retention_budget_or_free_space_floor")
    sample = output / "review-sample.jsonl"
    with sample.open("x", encoding="utf-8") as stream:
        stream.write(
            json.dumps(
                {"gate": "G5_REVIEW", "audit_identity": identity, "label_blind": True}
            )
            + "\n"
        )
        for flagged in (1, 0):
            for (
                pair_id,
                shared,
                denominator,
                disc,
                universe,
                aorg,
                ainc,
                borg,
                binc,
            ) in connection.execute(
                "SELECT p.pair_id,p.shared,p.denominator,p.discriminative,p.universe,a.org,a.incident,b.org,b.incident "
                "FROM pairs p JOIN nodes a ON a.id=p.a JOIN nodes b ON b.id=p.b "
                "WHERE p.flagged=? ORDER BY p.pair_id LIMIT 100",
                (flagged,),
            ):
                stream.write(
                    json.dumps(
                        {
                            "pair_id": pair_id,
                            "flagged": bool(flagged),
                            "left": [aorg, ainc],
                            "right": [borg, binc],
                            "shared": shared,
                            "union": denominator,
                            "shared_discriminative": disc,
                            "universe": universe,
                        },
                        sort_keys=True,
                    )
                    + "\n"
                )
    configuration_path = output / "configuration.json"
    configuration_path.write_text(
        json.dumps(configuration, indent=2) + "\n", encoding="utf-8"
    )
    if (
        sum(p.stat().st_size for p in output.iterdir()) + 1048576
        > budget.limits.retained_bytes
    ):
        raise AuditLimit("retained_artifacts_and_report_reserve")
    inventory: dict[str, object] = {
        p.name: {"bytes": p.stat().st_size, "sha256": sha(p)}
        for p in (path, sample, configuration_path)
    }
    budget.check()
    return inventory


def audit(
    g3: Path,
    g4: Path,
    lock: Path,
    schema: Path,
    manifest: Path,
    config_path: Path,
    scratch: Path,
    output: Path,
    *,
    benchmark_modulus: int | None = None,
    reviews: Path | None = None,
    progress: Callable[[str], None] = print,
) -> dict[str, object]:
    started = time.monotonic()
    config = load_audit_config(config_path)
    planning = preflight(
        g3, g4, lock, schema, manifest, config_path, scratch, output, benchmark_modulus
    )
    identity = fingerprint(
        {
            "config": config.sha256,
            "g4": config.document["g4"],
            "code": implementation_hashes(),
            "benchmark_modulus": benchmark_modulus,
        }
    )
    result: dict[str, object] = {
        "gate": "G5",
        "status": "INCOMPLETE",
        "training_allowed": False,
        "audit_identity": identity,
        "config_sha256": config.sha256,
        "code_sha256": implementation_hashes(),
        "g4": config.document["g4"],
        "benchmark_modulus": benchmark_modulus,
        "preflight": planning,
        "source_verified": False,
        "independent_g4_saved_output_verified_this_invocation": False,
        "g4_notebook_locator": "UNPINNED",
        "checks": {},
        "statistics": {},
        "failure": None,
        "warnings": [
            "No training/split authorization; G6-G8 unperformed.",
            "Benchmark excludes external incident relationships and cannot pass G5.",
            "Token equality after anonymization is not proof of real-world identity.",
            "Frozen snapshots cannot establish point-in-time availability or causality.",
            "Review sample is not complete clearance; unresolved registry/flags block.",
        ],
    }
    if not planning["feasible"]:
        result["failure"] = "resource_preflight"
        return result
    scratch.mkdir(parents=True)
    output.mkdir(parents=True)
    budget = Budget(scratch, config.limits)
    inputs = (g3 / "incidents.sqlite3", g3 / "report.json", g4)
    before = {
        p: (p.stat().st_size, p.stat().st_mtime_ns, p.stat().st_ino) for p in inputs
    }
    checks: dict[str, bool] = {
        "input_identity_verified": False,
        "complete_declared_scope": False,
        "row_accounting": False,
        "retained_memberships_reconciled": False,
        "identifier_provenance_resolved": False,
        "required_review_resolved": False,
        "component_accounting": False,
        "hard_edges_internal": False,
        "protected_artifacts_retained": False,
        "inputs_unchanged": False,
    }
    stats: dict[str, object] = {}
    phase = "verification"
    phases: dict[str, float] = {}
    connection: sqlite3.Connection | None = None
    old_temp_path = ""
    completed = False
    try:
        progress("G5: verifying pinned G3 v2 and saved G4 output; no reconstruction")
        contract, r3, r4 = verify_inputs(
            g3, g4, lock, schema, manifest, config, scratch
        )
        result["source_verified"] = True
        result["independent_g4_saved_output_verified_this_invocation"] = True
        result["g3"] = contract.g3
        checks["input_identity_verified"] = True
        budget.check()
        connection, old_temp_path = open_store(scratch, g3, budget)
        salt = cast(str, config.rules["benchmark_salt"])

        def selected(org: str, incident: str) -> int:
            key = json.dumps([org, incident], separators=(",", ":"))
            return int(
                benchmark_modulus is None
                or int.from_bytes(hashlib.sha256((salt + key).encode()).digest(), "big")
                % benchmark_modulus
                == 0
            )

        connection.create_function("selected", 2, selected, deterministic=True)
        connection.execute(
            "INSERT INTO nodes SELECT id,org,incident,retained,grade,alerts,id,id,id FROM "
            "(SELECT ROW_NUMBER() OVER(ORDER BY org,incident) AS id,org,incident,reason_mask=0 AS retained,"
            "CASE WHEN reason_mask=0 THEN grade ELSE NULL END AS grade,alerts FROM src.incidents WHERE selected(org,incident)=1)"
        )
        connection.commit()
        node_count, expected_rows = connection.execute(
            "SELECT COUNT(*),COALESCE(SUM(i.input_rows),0) FROM nodes n JOIN src.incidents i USING(org,incident)"
        ).fetchone()
        if benchmark_modulus is not None and (
            node_count > config.limits.benchmark_incidents
            or expected_rows > config.limits.benchmark_evidence_rows
        ):
            raise AuditLimit("benchmark_complete_incident_budget")
        if node_count == 0:
            raise AuditLimit("empty_benchmark_or_input")
        phase = "relationships"
        mark = time.monotonic()
        progress(
            "G5: indexed shared-alert relationships and complete incident selection"
        )
        stats["shared_alert_graph"] = shared = shared_alert_graph(connection, budget)
        phases[phase] = time.monotonic() - mark
        phase = "payload_diagnostics"
        mark = time.monotonic()
        progress("G5: one selected-payload pass; no model features fitted")
        extracted = ingest(
            connection,
            config,
            contract,
            schema,
            cast(list[str], r3["common_columns"]),
            budget,
        )
        stats.update(extracted)
        connection.execute("CREATE INDEX token_postings ON tokens(field,token,node)")
        stats["relationships"] = relationship_statistics(connection)
        stats["diagnostics"] = diagnostics(connection, config, budget)
        phases[phase] = time.monotonic() - mark
        phase = "candidate_search"
        mark = time.monotonic()
        progress("G5: label-independent bounded exact Jaccard candidates")
        stats["copy_candidates"] = find_pairs(connection, config, budget)
        phases[phase] = time.monotonic() - mark
        phase = "review_and_components"
        mark = time.monotonic()
        load_reviews(connection, reviews, identity, config, budget)
        stats["review"] = review = apply_reviews(connection, budget)
        sensitivity_graph(connection, budget)
        stats.update(summarize_components(connection, budget))
        retained = cast(int, stats["retained_incidents"])
        checks["row_accounting"] = extracted["evidence_rows_decoded"] == expected_rows
        relationships = stats["relationships"]
        duplicate_scopes = cast(
            dict[str, dict[str, int]], relationships["exact_duplicates"]
        )
        checks["row_accounting"] &= (
            sum(s["input_rows"] for s in duplicate_scopes.values()) == expected_rows
        )
        checks["complete_declared_scope"] = True
        actual_expected_memberships = connection.execute(
            "SELECT COALESCE(SUM(alerts),0) FROM nodes WHERE retained=1"
        ).fetchone()[0]
        checks["retained_memberships_reconciled"] = (
            shared["retained_local_memberships"] == actual_expected_memberships
        )
        if benchmark_modulus is None:
            g4stats = cast(dict[str, object], r4["statistics"])
            g3stats = cast(dict[str, object], r3["statistics"])
            checks["row_accounting"] &= expected_rows == g3stats["input_evidence_rows"]
            retained_rows = connection.execute(
                "SELECT COALESCE(SUM(i.input_rows),0) FROM nodes n JOIN src.incidents i USING(org,incident) WHERE n.retained=1"
            ).fetchone()[0]
            checks["retained_memberships_reconciled"] &= (
                retained == g4stats["projected_incidents"]
                and retained_rows == g4stats["retained_evidence_rows"]
                and actual_expected_memberships == g4stats["incident_local_alerts"]
            )
        checks["identifier_provenance_resolved"] = (
            all(
                r.status == "VERIFIED" and r.scope != "unresolved"
                for r in config.identifiers
            )
            and connection.execute(
                "SELECT COUNT(*) FROM tokens WHERE ambiguous=1"
            ).fetchone()[0]
            == 0
        )
        checks["required_review_resolved"] = (
            review["unresolved_pairs"] == 0 and review["unresolved_findings"] == 0
        )
        checks["component_accounting"] = (
            connection.execute(
                "SELECT COUNT(*) FROM nodes n JOIN component_ids c ON c.root=n.p_all"
            ).fetchone()[0]
            == node_count
        )
        checks["hard_edges_internal"] = (
            connection.execute(
                "SELECT COUNT(*) FROM edges e JOIN nodes a ON a.id=e.a JOIN nodes b ON b.id=e.b WHERE a.p_all<>b.p_all"
            ).fetchone()[0]
            == 0
        )
        phases[phase] = time.monotonic() - mark
        phase = "retention"
        result["artifacts"] = retain(
            connection, output, identity, budget, config.document
        )
        checks["protected_artifacts_retained"] = True
        completed = True
    except AuditLimit as error:
        result["failure"] = str(error)
    except KeyboardInterrupt:
        result["failure"] = "interrupted"
    except (LeakageError, ValueError, KeyError, TypeError):
        result["failure"] = "integrity_contract_or_review_failure"
        result["status"] = "BLOCKED"
    except sqlite3.Error as error:
        result["failure"] = budget.failure or (
            "sqlite_storage_limit"
            if getattr(error, "sqlite_errorcode", None) == sqlite3.SQLITE_FULL
            else "sqlite_audit_failure"
        )
        if (
            budget.failure is None
            and getattr(error, "sqlite_errorcode", None) != sqlite3.SQLITE_FULL
        ):
            result["status"] = "BLOCKED"
    finally:
        if connection is not None:
            close_store(connection, old_temp_path)
    checks["inputs_unchanged"] = all(
        before[p] == (p.stat().st_size, p.stat().st_mtime_ns, p.stat().st_ino)
        for p in before
    )
    if completed:
        result["status"] = (
            "PARTIAL"
            if benchmark_modulus is not None
            else ("PASSED" if all(checks.values()) else "BLOCKED")
        )
        if result["status"] == "BLOCKED":
            result["failure"] = "unresolved_clearance_checks"
    if not checks["inputs_unchanged"]:
        result["status"], result["failure"] = "BLOCKED", "accepted_inputs_changed"
    result.update(
        {
            "checks": checks,
            "statistics": stats,
            "completed_work": completed,
            "last_phase": phase,
            "phase_seconds": phases,
            "duration_seconds": round(time.monotonic() - started, 6),
            "peak_memory": peak_working_set(),
            "maximum_visible_scratch_bytes_lower_bound": budget.maximum_visible_bytes,
            "candidate_attempts": budget.candidate_attempts,
            "scratch_database_bytes": (scratch / "audit.sqlite3").stat().st_size
            if (scratch / "audit.sqlite3").exists()
            else 0,
            "runtime": {
                "python": platform.python_version(),
                "platform": platform.system(),
                "machine": platform.machine(),
            },
            "review_decisions_sha256": sha(reviews) if reviews is not None else None,
            "blocking_checks": sorted(
                name for name, passed in checks.items() if not passed
            ),
            "lineage_accepted": result["status"] == "PASSED",
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
