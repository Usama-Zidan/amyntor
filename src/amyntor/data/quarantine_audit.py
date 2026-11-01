"""Read-only G3 sensitivity audit; no reconstruction or quarantine changes."""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import shutil
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

from amyntor.data.incidents import (
    ReconstructionError,
    ResourceLimitError,
    encoded,
    peak_working_set,
    read_json,
    sha,
    verify_output,
)
from amyntor.data.schema_contract import load_contract

FIELDS = ("Timestamp", "DetectorId", "AlertTitle", "Category")
MODULI = (1, 10, 100)
SOURCES = ("GUIDE_Train.csv", "GUIDE_Test.csv")
SCENARIOS = {
    "current_global_four": ("global_mask", 15),
    "global_without_timestamp": ("global_mask", 14),
    "global_without_detector": ("global_mask", 13),
    "global_without_title": ("global_mask", 11),
    "global_without_category": ("global_mask", 7),
    "within_incident_four": ("local_mask", 15),
    "within_incident_without_timestamp": ("local_mask", 14),
    "no_metadata_quarantine_upper_bound": ("global_mask", 0),
}


def difference(first: tuple[str, ...], other: tuple[str, ...]) -> int:
    return sum(
        1 << i for i, (a, b) in enumerate(zip(first, other, strict=True)) if a != b
    )


@dataclass
class AlertState:
    """Constant state per scope: one tuple plus one per known source, never sets."""

    first: tuple[str, ...] | None = None
    sources: dict[str, tuple[str, ...]] = field(
        default_factory=lambda: dict[str, tuple[str, ...]]()
    )
    mask: int = 0
    within_source: int = 0
    within_incident: int = 0
    rows: int = 0
    incidents: int = 0

    def observe(self, values: tuple[str, ...], source: str) -> None:
        if source not in SOURCES:
            raise ReconstructionError("Unexpected G3 source partition")
        if self.first is None:
            self.first = values
        self.mask |= difference(self.first, values)
        previous = self.sources.setdefault(source, values)
        self.within_source |= difference(previous, values)
        self.rows += 1


DDL = """
CREATE TABLE alert_audit (
 org TEXT, alert TEXT, modulus INTEGER, mask INTEGER, local_mask INTEGER,
 source_mask INTEGER, incidents INTEGER, sources INTEGER, input_rows INTEGER
);
CREATE TABLE memberships (org TEXT, incident TEXT, alert TEXT, modulus INTEGER, mask INTEGER);
"""


def project(
    connection: sqlite3.Connection, columns: list[str], progress: Callable[[str], None]
) -> int:
    """Stream existing alert index; iterator grouping does not materialize alerts."""
    positions = [columns.index(name) for name in FIELDS]
    rows = 0
    cursor = connection.execute(
        "SELECT org,alert,incident,source,payload FROM src.evidence "
        "INDEXED BY evidence_alert ORDER BY org,alert,incident"
    )
    for (org, alert), alert_rows in itertools.groupby(cursor, lambda r: (r[0], r[1])):
        states = {modulus: AlertState() for modulus in MODULI}
        for incident, evidence in itertools.groupby(alert_rows, lambda r: r[2]):
            bucket = int.from_bytes(
                hashlib.sha256(encoded([org, incident]).encode()).digest()[:8], "big"
            )
            selected = [modulus for modulus in MODULI if bucket % modulus == 0]
            first: tuple[str, ...] | None = None
            mask = 0
            for _, _, _, source, payload in evidence:
                if len(payload) > 1048576:
                    raise ReconstructionError("G3 payload exceeds audit bound")
                values: object = json.loads(payload)
                if not isinstance(values, list):
                    raise ReconstructionError("Unsupported G3 payload representation")
                candidates = cast(list[object], values)
                if len(candidates) != len(columns) or not all(
                    isinstance(value, str) for value in candidates
                ):
                    raise ReconstructionError("Unsupported G3 payload representation")
                cells = cast(list[str], candidates)
                fields = tuple(cells[position] for position in positions)
                if first is None:
                    first = fields
                mask |= difference(first, fields)
                for modulus in selected:
                    states[modulus].observe(fields, source)
                rows += 1
                if rows % 1000000 == 0:
                    progress(f"Audited {rows} evidence rows")
                if rows % 2048 == 0:
                    connection.commit()
            for modulus in selected:
                state = states[modulus]
                state.within_incident |= mask
                state.incidents += 1
                connection.execute(
                    "INSERT INTO memberships VALUES (?,?,?,?,?)",
                    (org, incident, alert, modulus, mask),
                )
        for modulus, state in states.items():
            if state.rows:
                connection.execute(
                    "INSERT INTO alert_audit VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        org,
                        alert,
                        modulus,
                        state.mask,
                        state.within_incident,
                        state.within_source,
                        state.incidents,
                        len(state.sources),
                        state.rows,
                    ),
                )
    connection.commit()
    return rows


def summaries(connection: sqlite3.Connection) -> dict[str, object]:
    connection.execute(
        "CREATE UNIQUE INDEX audited_alerts ON alert_audit(org,alert,modulus)"
    )

    # Four MAX booleans implement a bounded bitwise OR, including overlapping alerts.
    def mask_sql(column: str) -> str:
        return "+".join(f"{bit}*MAX(({column}&{bit})<>0)" for bit in (1, 2, 4, 8))

    connection.execute(
        "CREATE TABLE incident_audit AS SELECT m.org,m.incident,m.modulus,"
        f"{mask_sql('a.mask')} AS global_mask,{mask_sql('m.mask')} AS local_mask,"
        "i.reason_mask,i.grade,i.input_rows FROM memberships m JOIN alert_audit a "
        "USING(org,alert,modulus) JOIN src.incidents i USING(org,incident) "
        "GROUP BY m.org,m.incident,m.modulus"
    )
    connection.commit()
    result: dict[str, object] = {}
    for modulus in MODULI:
        alerts: list[dict[str, object]] = []
        for (
            mask,
            local,
            source,
            reused,
            cross_source,
            count,
            rows,
        ) in connection.execute(
            "SELECT mask,local_mask,source_mask,incidents>1,sources>1,COUNT(*),SUM(input_rows) "
            "FROM alert_audit WHERE modulus=? GROUP BY 1,2,3,4,5 ORDER BY 1,2,3,4,5",
            (modulus,),
        ):
            alerts.append(
                {
                    "mask": mask,
                    "within_incident_mask": local,
                    "within_source_mask": source,
                    "multiple_incidents": bool(reused),
                    "multiple_sources": bool(cross_source),
                    "alerts": count,
                    "evidence_rows_on_these_alerts": rows,
                }
            )
        fields: dict[str, object] = {}
        for i, name in enumerate(FIELDS):
            bit = 1 << i
            counts = connection.execute(
                "SELECT COALESCE(SUM((mask&?)<>0),0),"
                "COALESCE(SUM((mask&?)<>0 AND (local_mask&?)=0),0),"
                "COALESCE(SUM((mask&?)<>0 AND (source_mask&?)=0),0) "
                "FROM alert_audit WHERE modulus=?",
                (bit, bit, bit, bit, bit, modulus),
            ).fetchone()
            impact = connection.execute(
                "SELECT COUNT(*),COALESCE(SUM(input_rows),0) FROM incident_audit "
                "WHERE modulus=? AND (global_mask&?)<>0",
                (modulus, bit),
            ).fetchone()
            fields[name] = dict(
                zip(
                    (
                        "conflicting_alerts",
                        "across_incidents_only_alerts",
                        "across_sources_only_alerts",
                        "affected_incidents",
                        "rows_on_affected_incidents",
                    ),
                    (*counts, *impact),
                    strict=True,
                )
            )
        scenarios: dict[str, object] = {}
        for name, (column, mask) in SCENARIOS.items():
            # Other quarantine reasons survive every counterfactual. Never assign
            # the diagnostic MIN grade to incidents with missing/conflicting labels.
            retained = f"(reason_mask&7)=0 AND ({column}&{mask})=0"
            row = connection.execute(
                f"SELECT COUNT(*),COALESCE(SUM({retained}),0),"
                f"COALESCE(SUM(CASE WHEN {retained} THEN input_rows ELSE 0 END),0) "
                "FROM incident_audit WHERE modulus=?",
                (modulus,),
            ).fetchone()
            labels = dict(
                connection.execute(
                    f"SELECT grade,COUNT(*) FROM incident_audit WHERE modulus=? AND {retained} "
                    "GROUP BY grade ORDER BY grade",
                    (modulus,),
                )
            )
            scenarios[name] = {
                "incidents": row[0],
                "retained": row[1],
                "quarantined": row[0] - row[1],
                "retained_input_rows": row[2],
                "retained_incident_labels": labels,
            }
        context = connection.execute(
            "SELECT COUNT(*),COALESCE(SUM(reason_mask<>0),0),"
            "COALESCE(SUM((reason_mask&8)<>0),0),"
            "COALESCE(SUM((reason_mask&8)<>0 AND global_mask=0),0) "
            "FROM incident_audit WHERE modulus=?",
            (modulus,),
        ).fetchone()
        result[str(modulus)] = {
            "field_counts": fields,
            "alert_combinations": alerts,
            "scenarios": scenarios,
            "full_context_on_same_selected_incidents": {
                "incidents": context[0],
                "quarantined": context[1],
                "metadata_conflict_incidents": context[2],
                "metadata_conflicts_invisible_in_subset": context[3],
            },
        }
    return result


def audit(
    g3_output: Path,
    lock: Path,
    contract: Path,
    scratch: Path,
    *,
    max_seconds: int = 7200,
    max_scratch_bytes: int = 16 * 1024**3,
    minimum_free_bytes: int = 2 * 1024**3,
    preflight_only: bool = False,
    benchmark_reports: tuple[Path, ...] = (),
    progress: Callable[[str], None] = print,
) -> dict[str, object]:
    """Cryptographically reverify accepted G3, then read it through mode=ro."""
    started = time.monotonic()
    if (
        min(max_seconds, max_scratch_bytes, minimum_free_bytes) <= 0
        or len(benchmark_reports) > 2
    ):
        raise ReconstructionError("Unsupported audit resource bounds")
    if scratch.exists() or scratch.resolve().is_relative_to(g3_output.resolve()):
        raise ReconstructionError(
            "Choose fresh scratch outside the accepted G3 directory"
        )
    report = read_json(g3_output / "report.json")
    database = g3_output / "incidents.sqlite3"
    if database.is_symlink() or not database.is_file():
        raise ReconstructionError("G3 database must be a regular non-symlink file")
    for suffix in ("-wal", "-shm", "-journal"):
        if database.with_name(database.name + suffix).exists():
            raise ReconstructionError("Audit requires a closed standalone G3 database")
    identity = cast(dict[str, object], report["reconstruction_identity"])
    statistics = cast(dict[str, int], report["statistics"])
    columns = cast(list[str], report["common_columns"])
    schema = load_contract(contract)
    expected_columns = [
        name
        for name in schema.files[0].header
        if all(name in source.header for source in schema.files)
    ]
    if (
        columns != expected_columns
        or len(columns) != 45
        or len(set(columns)) != 45
        or any(f not in columns for f in FIELDS)
    ):
        raise ReconstructionError("Unsupported G3 payload columns")
    ancestor = scratch.resolve().parent
    while not ancestor.exists():
        ancestor = ancestor.parent
    free = shutil.disk_usage(ancestor).free
    # Planning envelope for three scope/membership projections plus disk sorting.
    estimate = (
        statistics["input_evidence_rows"] * 384
        + statistics["unique_scoped_alerts"] * 1152
        + statistics["unique_incidents"] * 512
    )
    preflight = {
        "filesystem_checked": str(ancestor),
        "available_bytes": free,
        "estimated_scratch_bytes": estimate,
        "minimum_free_bytes": minimum_free_bytes,
        "max_scratch_bytes": max_scratch_bytes,
        "feasible": free >= estimate + minimum_free_bytes
        and estimate <= max_scratch_bytes,
    }
    if preflight_only:
        return {
            "status": "PREFLIGHT_ONLY",
            "preflight": preflight,
            "source_verified": False,
        }
    if not preflight["feasible"]:
        raise ResourceLimitError("Audit scratch preflight failed")
    scratch.mkdir(parents=True)
    config = scratch / "original-reconstruction-config.json"
    config.write_text(json.dumps(identity["configuration"]), encoding="utf-8")
    # Reuse the G3 verifier including G1 lock, G2 contract, original code identity
    # and full database hash. It reads no source CSV and writes no source artifact.
    progress("Verifying existing G3 artifact identity and database SHA-256")
    verified = verify_output(g3_output, lock, contract, config)
    before = database.stat()
    scratch_db = scratch / "audit.sqlite3"
    previous_temp: str | None = None
    result: dict[str, object] = {}
    failure: str | None = None
    maximum_visible_scratch_bytes = 0
    with sqlite3.connect(scratch_db, uri=True) as connection:
        connection.execute("PRAGMA cache_size=-65536")
        connection.execute("PRAGMA mmap_size=0")
        connection.execute("PRAGMA threads=1")
        connection.execute("PRAGMA temp_store=FILE")
        previous = connection.execute("PRAGMA temp_store_directory").fetchone()
        previous_temp = previous[0] if previous else None
        temp = scratch / "sqlite-temp"
        temp.mkdir()
        connection.execute(
            "PRAGMA temp_store_directory='" + str(temp).replace("'", "''") + "'"
        )
        connection.execute(f"PRAGMA max_page_count={max_scratch_bytes // 4096}")
        connection.execute(
            "ATTACH DATABASE ? AS src", (database.resolve().as_uri() + "?mode=ro",)
        )
        last_check = 0.0

        def check_resources() -> int:
            nonlocal last_check, failure, maximum_visible_scratch_bytes
            now = time.monotonic()
            if now - last_check < 1:
                return 0
            last_check = now
            maximum_visible_scratch_bytes = max(
                maximum_visible_scratch_bytes,
                sum(p.stat().st_size for p in scratch.rglob("*") if p.is_file()),
            )
            if (
                now - started > max_seconds
                or shutil.disk_usage(scratch).free < minimum_free_bytes
            ):
                failure = "time_or_disk_limit"
                return 1
            return 0

        connection.set_progress_handler(check_resources, 10000)
        try:
            connection.executescript(DDL)
            progress("Streaming read-only evidence through existing alert index")
            count = project(connection, columns, progress)
            progress("Computing aggregate conflicts and counterfactual counts")
            result = summaries(connection)
            baseline = cast(
                dict[str, object], cast(dict[str, object], result["1"])["scenarios"]
            )
            current = cast(dict[str, object], baseline["current_global_four"])
            alert_count = connection.execute(
                "SELECT COUNT(*) FROM alert_audit WHERE modulus=1 AND mask<>0"
            ).fetchone()[0]
            disagreements = connection.execute(
                "SELECT COUNT(*) FROM incident_audit WHERE modulus=1 "
                "AND ((global_mask<>0)<>((reason_mask&8)<>0))"
            ).fetchone()[0]
            checks = {
                "evidence_rows": count == statistics["input_evidence_rows"],
                "incidents": current["incidents"] == statistics["unique_incidents"],
                "retained_incidents": current["retained"]
                == statistics["retained_labeled_incidents"],
                "conflicting_alerts": alert_count
                == statistics["conflicting_scoped_alerts"],
                "metadata_quarantine_membership": disagreements == 0,
                "labels": current["retained_incident_labels"]
                == statistics["retained_incident_labels"],
            }
            if not all(checks.values()):
                failure = "G3_reconciliation_failed"
        except sqlite3.OperationalError:
            failure = failure or "sqlite_resource_or_query_failure"
            checks = {"complete": False}
        finally:
            connection.set_progress_handler(None, 0)
            connection.execute(
                "PRAGMA temp_store_directory='"
                + (previous_temp or "").replace("'", "''")
                + "'"
            )
    after = database.stat()
    checks["source_metadata_unchanged"] = (
        before.st_size,
        before.st_mtime_ns,
        before.st_ino,
    ) == (after.st_size, after.st_mtime_ns, after.st_ino)
    comparisons: list[dict[str, object]] = []
    for path in benchmark_reports:
        benchmark = read_json(path)
        benchmark_identity = cast(
            dict[str, object], benchmark["reconstruction_identity"]
        )
        comparable = all(
            benchmark_identity.get(key) == identity.get(key)
            for key in (
                "source_identity",
                "contract_sha256",
                "configuration",
                "implementation_sha256",
            )
        )
        modulus = benchmark_identity.get("benchmark_modulus")
        observed = cast(dict[str, object], benchmark["statistics"])
        replay: dict[str, object] | None = None
        if str(modulus) in result:
            selected_scope = cast(dict[str, object], result[str(modulus)])
            selected_scenarios = cast(
                dict[str, dict[str, object]], selected_scope["scenarios"]
            )
            replay = selected_scenarios["current_global_four"]
        comparisons.append(
            {
                "report_sha256": sha(path),
                "benchmark_modulus": modulus,
                "matching_identity_except_sampling": comparable,
                "reported_status": benchmark.get("status"),
                "reported_incidents": observed.get("unique_incidents"),
                "reported_quarantined_incidents": observed.get("quarantined_incidents"),
                "reported_conflicting_alerts": observed.get(
                    "conflicting_scoped_alerts"
                ),
                "reported_failure_present": benchmark.get("failure") is not None,
                "replay_matches_incident_and_quarantine_counts": (
                    replay["incidents"] == observed.get("unique_incidents")
                    and replay["quarantined"] == observed.get("quarantined_incidents")
                    if replay is not None
                    else None
                ),
            }
        )
    return {
        "audit_version": "guide-g3-quarantine-audit-1",
        "status": "COMPLETE" if not failure and all(checks.values()) else "INCOMPLETE",
        "changes_to_G3": False,
        "training_allowed": False,
        "failure": failure,
        "source_verification": verified,
        "g3_report_sha256": sha(g3_output / "report.json"),
        "g3_database": report["database"],
        "source_identity": identity["source_identity"],
        "audit_code_sha256": sha(Path(__file__)),
        "field_bits": {name: 1 << i for i, name in enumerate(FIELDS)},
        "preflight": preflight,
        "max_seconds": max_seconds,
        "scopes": result,
        "checks": checks,
        "benchmark_reports": comparisons,
        "duration_seconds": round(time.monotonic() - started, 6),
        "peak_memory": peak_working_set(),
        "scratch_database_bytes": scratch_db.stat().st_size,
        "maximum_visible_scratch_bytes_lower_bound": maximum_visible_scratch_bytes,
        "warnings": [
            "Counterfactuals are sensitivity estimates, not approved quarantine rules.",
            "Counts establish variation and scope, not update/anonymization/reuse causality.",
            "Moduli 100 and 10 replay original incident-hash selection on the full artifact.",
            "Evidence rows on conflicting alerts differ from all rows on affected incidents.",
            "Exact duplicate rows cannot create distinct field values; counts retain multiplicities.",
            "Peak temporary disk is not measured; file-backed sorts also obey the free-space floor.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--g3-output", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--benchmark-reports", type=Path, nargs="*", default=[])
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--max-seconds", type=int, default=7200)
    parser.add_argument("--max-scratch-bytes", type=int, default=16 * 1024**3)
    parser.add_argument("--minimum-free-bytes", type=int, default=2 * 1024**3)
    args = parser.parse_args()
    if args.report.exists() or args.report.resolve().is_relative_to(
        args.g3_output.resolve()
    ):
        parser.error("Choose a new report outside the accepted G3 directory")
    try:
        report = audit(
            args.g3_output,
            args.lock,
            args.contract,
            args.scratch,
            max_seconds=args.max_seconds,
            max_scratch_bytes=args.max_scratch_bytes,
            minimum_free_bytes=args.minimum_free_bytes,
            preflight_only=args.preflight_only,
            benchmark_reports=tuple(args.benchmark_reports),
        )
    except (ValueError, OSError, KeyError, sqlite3.Error, ResourceLimitError) as error:
        print(f"Audit rejected ({type(error).__name__}); no G3 changes made.")
        return 2
    if args.preflight_only:
        print(json.dumps(report, sort_keys=True))
        return 0 if cast(dict[str, object], report["preflight"])["feasible"] else 1
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {"status": report["status"], "checks": report["checks"]}, sort_keys=True
        )
    )
    return 0 if report["status"] == "COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
