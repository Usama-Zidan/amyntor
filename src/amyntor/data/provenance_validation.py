"""Bounded G4 validation on an unchanged, verified G3 v2 SQLite artifact."""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import cast

from amyntor.data.incidents import (
    encoded,
    peak_working_set,
    read_json,
    sha,
    verify_output,
)
from amyntor.data.provenance import CANDIDATES, COUNT, ProvenanceError, load_provenance
from amyntor.data.schema_contract import fingerprint, load_contract
from amyntor.features.incident_snapshot import (
    ProjectionLimitError,
    accepted_values,
    contribution,
)


@dataclass(frozen=True)
class ValidationLimits:
    batch_rows: int = 2048
    batch_bytes: int = 4194304
    field_chars: int = 65536
    payload_chars: int = 8388608
    cache_mib: int = 64
    max_seconds: int = 7200
    max_database_bytes: int = 17179869184
    minimum_free_bytes: int = 2147483648


DEFAULT_LIMITS = ValidationLimits()


def validate_g4(
    g3_output: Path,
    lock_path: Path,
    schema_path: Path,
    manifest_path: Path,
    scratch: Path,
    *,
    limits: ValidationLimits = DEFAULT_LIMITS,
    max_evidence_rows: int | None = None,
    preflight_only: bool = False,
    progress: Callable[[str], None] = print,
) -> dict[str, object]:
    started = time.monotonic()
    if any(type(v) is not int or v <= 0 for v in asdict(limits).values()) or (
        max_evidence_rows is not None and max_evidence_rows <= 0
    ):
        raise ProvenanceError("Positive validation bounds required")
    if scratch.exists() or scratch.resolve().is_relative_to(g3_output.resolve()):
        raise ProvenanceError("Choose fresh scratch outside accepted G3 output")
    contract = load_provenance(manifest_path, schema_path)
    report_path, database = g3_output / "report.json", g3_output / "incidents.sqlite3"
    for path in (report_path, database):
        if path.is_symlink() or not path.is_file():
            raise ProvenanceError("G3 requires regular non-symlink artifact files")
    if any(
        database.with_name(database.name + suffix).exists()
        for suffix in ("-wal", "-shm", "-journal")
    ):
        raise ProvenanceError("G3 must be a closed standalone SQLite artifact")
    if (
        sha(report_path) != contract.g3["report_sha256"]
        or database.stat().st_size != contract.g3["database_bytes"]
    ):
        raise ProvenanceError("G3 report/size differs from trusted manifest")
    source_report = read_json(report_path)
    identity = cast(dict[str, object], source_report["reconstruction_identity"])
    if (
        source_report["reconstruction_sha256"] != contract.g3["reconstruction_sha256"]
        or cast(dict[str, object], source_report["database"])["sha256"]
        != contract.g3["database_sha256"]
        or cast(dict[str, object], identity["configuration"])["version"]
        != "guide-v1-reconstruction-2"
    ):
        raise ProvenanceError("G3 must match accepted reconstruction v2")
    schema = load_contract(schema_path)
    columns = [
        name
        for name in schema.files[0].header
        if all(name in file.header for file in schema.files)
    ]
    if source_report["common_columns"] != columns:
        raise ProvenanceError("G3 payload column order differs from G2 contract")
    source_stats = cast(dict[str, object], source_report["statistics"])
    ancestor = scratch.resolve().parent
    while not ancestor.exists():
        ancestor = ancestor.parent
    estimate = (
        int(cast(int, source_stats["input_evidence_rows"]))
        * (64 + 192 * len(contract.categorical))
        * 2
    )
    free = shutil.disk_usage(ancestor).free
    preflight = {
        "checked_filesystem_path": str(ancestor),
        "available_bytes": free,
        "estimated_processing_bytes": estimate,
        "minimum_free_bytes": limits.minimum_free_bytes,
        "basis": "Two planning passes over row-count times narrow projection size; not a guaranteed maximum",
        "feasible": free >= estimate + limits.minimum_free_bytes
        and estimate <= limits.max_database_bytes,
    }
    checks: dict[str, bool] = {
        "candidate_decisions_resolved": all(
            contract.fields[n].status != "UNRESOLVED" for n in CANDIDATES
        ),
        "minimum_contract": contract.ready,
    }
    base: dict[str, object] = {
        "gate": "G4",
        "status": "BLOCKED",
        "training_allowed": False,
        "g5_g8_performed": False,
        "manifest_sha256": contract.sha256,
        "g3": contract.g3,
        "accepted_fields": list(contract.accepted),
        "candidate_decisions": {
            name: contract.fields[name].status for name in CANDIDATES
        },
        "preflight": preflight,
        "limits": asdict(limits),
        "checks": checks,
        "max_evidence_rows": max_evidence_rows,
    }
    if preflight_only:
        return {**base, "status": "PREFLIGHT_ONLY", "source_verified": False}
    if not all(checks.values()):
        return {
            **base,
            "failure": "provenance_contract_incomplete",
            "source_verified": False,
        }
    if not preflight["feasible"]:
        return {
            **base,
            "status": "INCOMPLETE",
            "failure": "storage_preflight",
            "source_verified": False,
        }
    scratch.mkdir(parents=True)
    config = scratch / "original-g3-config.json"
    config.write_text(json.dumps(identity["configuration"]), encoding="utf-8")
    progress("Verifying pinned saved G3 v2 output; no reconstruction")
    verified = verify_output(g3_output, lock_path, schema_path, config)
    before = {
        p: (p.stat().st_size, p.stat().st_mtime_ns, p.stat().st_ino)
        for p in (database, report_path)
    }
    positions = {name: columns.index(name) for name in CANDIDATES if name != COUNT}
    probes: dict[str, dict[str, int]] = {
        name: {"empty_rows": 0, "literal_null_like_rows": 0, "sentinel_probe_rows": 0}
        for name in positions
    }
    rows = 0
    complete = False
    statistics: dict[str, object] = {}
    failure: str | None = None
    maximum_visible_bytes = 0
    connection = sqlite3.connect(scratch / "projection.sqlite3", uri=True)
    old_temp = connection.execute("PRAGMA temp_store_directory").fetchone()
    old_temp_path = str(old_temp[0]) if old_temp else ""
    last_check = 0.0

    def guard() -> None:
        nonlocal last_check, maximum_visible_bytes
        now = time.monotonic()
        if now - started > limits.max_seconds:
            raise ProjectionLimitError("time_limit")
        if now - last_check >= 1:
            last_check = now
            if shutil.disk_usage(scratch).free < limits.minimum_free_bytes:
                raise ProjectionLimitError("disk_floor")
            maximum_visible_bytes = max(
                maximum_visible_bytes,
                sum(p.stat().st_size for p in scratch.rglob("*") if p.is_file()),
            )

    def sql_guard() -> int:
        nonlocal failure
        try:
            guard()
        except ProjectionLimitError as error:
            failure = str(error)
            return 1
        return 0

    try:
        guard()
        temp = scratch / "sqlite-temp"
        temp.mkdir()
        quoted = str(temp.resolve()).replace("'", "''")
        connection.execute(f"PRAGMA temp_store_directory='{quoted}'")
        actual = connection.execute("PRAGMA temp_store_directory").fetchone()
        if not actual or actual[0] != str(temp.resolve()):
            raise ProvenanceError("SQLite temporary-directory control unavailable")
        connection.execute("PRAGMA temp_store=FILE")
        connection.execute("PRAGMA mmap_size=0")
        connection.execute("PRAGMA threads=1")
        connection.execute(f"PRAGMA cache_size=-{limits.cache_mib * 1024}")
        page_size = connection.execute("PRAGMA page_size").fetchone()[0]
        connection.execute(
            f"PRAGMA max_page_count={max(1, limits.max_database_bytes // page_size)}"
        )
        connection.execute(
            "ATTACH DATABASE ? AS src", (database.resolve().as_uri() + "?mode=ro",)
        )
        connection.set_progress_handler(sql_guard, 10000)
        connection.executescript("""
            CREATE TABLE alerts AS SELECT m.org,m.incident,m.alert FROM src.incident_alerts m
              JOIN src.incidents i USING(org,incident) WHERE i.reason_mask=0;
            CREATE UNIQUE INDEX alert_keys ON alerts(org,incident,alert);
            CREATE TABLE values_per_alert (org TEXT,incident TEXT,alert TEXT,field TEXT,value TEXT,
              PRIMARY KEY(org,incident,alert,field,value)) WITHOUT ROWID;
        """)
        batch: list[tuple[str, ...]] = []
        batch_bytes = 0

        def flush() -> None:
            nonlocal batch_bytes
            guard()
            connection.executemany(
                "INSERT OR IGNORE INTO values_per_alert VALUES (?,?,?,?,?)", batch
            )
            connection.commit()
            batch.clear()
            batch_bytes = 0

        cursor = connection.execute(
            "SELECT e.org,e.incident,e.alert,e.payload FROM src.evidence e JOIN src.incidents i USING(org,incident) WHERE i.reason_mask=0"
        )
        for org, incident, alert, payload in cursor:
            if max_evidence_rows is not None and rows >= max_evidence_rows:
                failure = "explicit_evidence_row_limit"
                break
            if len(payload) > limits.payload_chars:
                raise ProjectionLimitError("payload_limit")
            decoded: object = json.loads(payload)
            if not isinstance(decoded, list):
                raise ProvenanceError("Malformed G3 payload")
            cells = cast(list[object], decoded)
            if len(cells) != len(columns) or any(not isinstance(v, str) for v in cells):
                raise ProvenanceError("Incompatible G3 payload")
            values = cast(list[str], cells)
            for name, position in positions.items():
                value = values[position]
                if len(value) > limits.field_chars:
                    raise ProjectionLimitError("candidate_field_limit")
                probes[name]["empty_rows"] += int(value == "")
                probes[name]["literal_null_like_rows"] += int(
                    value in schema.null_tokens
                )
                probes[name]["sentinel_probe_rows"] += int(
                    value in schema.sentinel_tokens
                )
            selected = accepted_values(
                {name: values[positions[name]] for name in contract.categorical},
                contract,
                limits.field_chars,
            )
            for name, value in selected:
                record = (org, incident, alert, name, value)
                cost = sum(len(v) * 2 for v in record) + 256
                if cost > limits.batch_bytes:
                    raise ProjectionLimitError("single_projection_record_limit")
                if (
                    batch_bytes + cost > limits.batch_bytes
                    or len(batch) >= limits.batch_rows
                ):
                    flush()
                batch.append(record)
                batch_bytes += cost
            rows += 1
            if rows % limits.batch_rows == 0:
                flush()
            if rows % 1000000 == 0:
                progress(f"Validated {rows} retained evidence rows")
        else:
            complete = True
        flush()
        connection.executescript("""
            CREATE TABLE incident_counts AS SELECT org,incident,COUNT(*) AS alerts
              FROM alerts GROUP BY org,incident;
            CREATE UNIQUE INDEX incident_keys ON incident_counts(org,incident);
            CREATE TABLE feature_counts AS SELECT org,incident,field,value,COUNT(*) AS numerator
              FROM values_per_alert GROUP BY org,incident,field,value;
        """)
        total_incidents = connection.execute(
            "SELECT COUNT(*) FROM incident_counts"
        ).fetchone()[0]
        total_alerts = connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        expected_rows, expected_alerts = connection.execute(
            "SELECT COALESCE(SUM(input_rows),0),COALESCE(SUM(alerts),0) FROM src.incidents WHERE reason_mask=0"
        ).fetchone()
        missing = connection.execute(
            "SELECT COUNT(*) FROM alerts a WHERE (SELECT COUNT(DISTINCT field) FROM values_per_alert v WHERE v.org=a.org AND v.incident=a.incident AND v.alert=a.alert)<>?",
            (len(contract.categorical),),
        ).fetchone()[0]
        digest = hashlib.sha256()
        projected_incidents = 0
        previous: tuple[str, str] | None = None
        for org, incident, field, value, numerator, denominator in connection.execute(
            "SELECT f.org,f.incident,f.field,f.value,f.numerator,i.alerts FROM feature_counts f JOIN incident_counts i USING(org,incident) ORDER BY f.org,f.incident,f.field,f.value"
        ):
            contribution(value, numerator, denominator)  # shared projection semantics
            if previous != (org, incident):
                digest.update(
                    (
                        encoded(["incident", org, incident, str(denominator)]) + "\n"
                    ).encode()
                )
                previous = (org, incident)
                projected_incidents += 1
            digest.update(
                (
                    encoded([field, value, str(numerator), str(denominator)]) + "\n"
                ).encode()
            )
        checks.update(
            {
                "complete_retained_scan": complete and max_evidence_rows is None,
                "retained_rows_reconciled": rows == expected_rows,
                "retained_incidents_reconciled": total_incidents
                == source_stats["retained_labeled_incidents"]
                == projected_incidents,
                "distinct_alerts_reconciled": total_alerts == expected_alerts,
                "per_alert_fields_complete": missing == 0,
            }
        )
        statistics = {
            "retained_evidence_rows": rows,
            "projected_incidents": projected_incidents,
            "incident_local_alerts": total_alerts,
            "candidate_lexical_probes": probes,
            "unfitted_projection_sha256": digest.hexdigest(),
            "projection_digest_spec": "sorted-incident-keys-alert-count-and-field-value-rational-contributions-v1",
        }
    except ProjectionLimitError as error:
        failure = str(error)
    except (ProvenanceError, json.JSONDecodeError):
        failure = "incompatible_projection_data"
    except sqlite3.Error as error:
        failure = failure or (
            "sqlite_resource_limit"
            if getattr(error, "sqlite_errorcode", None) == sqlite3.SQLITE_FULL
            else "sqlite_validation_failure"
        )
    finally:
        connection.set_progress_handler(None, 0)
        connection.rollback()
        connection.execute(
            "PRAGMA temp_store_directory='" + old_temp_path.replace("'", "''") + "'"
        )
        connection.close()
    checks["source_metadata_unchanged"] = all(
        before[p] == (p.stat().st_size, p.stat().st_mtime_ns, p.stat().st_ino)
        for p in before
    )
    status = (
        "PASSED"
        if failure is None and all(checks.values()) and complete
        else "INCOMPLETE"
    )
    if (
        failure in ("incompatible_projection_data", "sqlite_validation_failure")
        or not checks["source_metadata_unchanged"]
        or (
            complete
            and not all(
                value
                for name, value in checks.items()
                if name != "complete_retained_scan"
            )
            and failure is None
        )
    ):
        status = "BLOCKED"
    if max_evidence_rows is not None and status != "BLOCKED":
        status = "INCOMPLETE"
    result = {
        **base,
        "status": status,
        "source_verified": True,
        "source_verification": verified,
        "failure": failure,
        "statistics": statistics,
        "checks": checks,
        "code_sha256": {
            p.name: sha(p)
            for p in (
                Path(__file__),
                Path(__file__).with_name("provenance.py"),
                Path(__file__).with_name("validate_g4.py"),
                Path(__file__).parents[1] / "features/incident_snapshot.py",
            )
        },
        "duration_seconds": round(time.monotonic() - started, 6),
        "peak_memory": peak_working_set(),
        "scratch_database_bytes": (scratch / "projection.sqlite3").stat().st_size,
        "maximum_visible_scratch_bytes_lower_bound": maximum_visible_bytes,
        "warnings": [
            "Retrospective context only; point-in-time availability unproven.",
            "Field decisions are not G5 statistical leakage clearance or G8 training authorization.",
            "Opaque grouping keys occur only in private scratch/integrity digest, never model values or published records.",
            "Literal null/sentinel probes are not semantic missingness mappings.",
            "Global alert relationships remain unchanged in source G3 for G5/G6.",
            "Sampled/limited runs cannot pass G4; temporary disk observations exclude invisible SQLite files.",
        ],
    }
    result["validation_sha256"] = fingerprint(
        {
            "manifest_sha256": contract.sha256,
            "g3": contract.g3,
            "limits": asdict(limits),
            "max_evidence_rows": max_evidence_rows,
            "code_sha256": result["code_sha256"],
            "checks": checks,
            "statistics": statistics,
            "status": status,
        }
    )
    return result
