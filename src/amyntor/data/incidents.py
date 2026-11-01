"""G3 reconstruction orchestration with bounded CSV ingestion and disk state."""

from __future__ import annotations

import csv
import hashlib
import json
import platform
import shutil
import sqlite3
import sys
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import cast

from amyntor.data.acquisition import verify_files
from amyntor.data.incident_preflight import storage_preflight
from amyntor.data.incident_store import DDL, summarize
from amyntor.data.schema import RecordLines, ScanLimits
from amyntor.data.schema_contract import LABELS, fingerprint, load_contract


class ReconstructionError(ValueError):
    """Fail-closed reconstruction or unsupported configuration."""


class ResourceLimitError(RuntimeError):
    """A partial run cannot pass G3."""


@dataclass(frozen=True)
class ReconstructionConfig:
    version: str
    canonicalization: str
    alert_invariants: tuple[str, ...]
    batch_rows: int
    batch_bytes: int
    cache_mib: int
    database_estimate_multiplier: int
    temporary_estimate_multiplier: int
    max_database_bytes: int
    minimum_free_bytes: int
    max_seconds: int


def read_json(path: Path, maximum: int = 1048576) -> dict[str, object]:
    with path.open("rb") as stream:
        payload = stream.read(maximum + 1)
    if len(payload) > maximum:
        raise ReconstructionError("Metadata exceeds configured bound")
    try:
        value: object = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError):
        raise ReconstructionError("Invalid reconstruction metadata JSON") from None
    if not isinstance(value, dict):
        raise ReconstructionError("Metadata must be an object")
    return cast(dict[str, object], value)


def load_config(path: Path) -> ReconstructionConfig:
    doc = read_json(path, 16384)
    if set(doc) != set(ReconstructionConfig.__dataclass_fields__):
        raise ReconstructionError("Unexpected reconstruction configuration fields")
    if (
        doc["version"] not in ("guide-v1-reconstruction-1", "guide-v1-reconstruction-2")
        or doc["canonicalization"] != "ordered-common-columns-json-v1"
        or doc["alert_invariants"]
        != ["Timestamp", "DetectorId", "AlertTitle", "Category"]
    ):
        raise ReconstructionError("Unsupported reconstruction rules")
    for key in set(doc) - {"version", "canonicalization", "alert_invariants"}:
        value = doc[key]
        if type(value) is not int or value <= 0:
            raise ReconstructionError("Resource bounds must be positive integers")
    return ReconstructionConfig(
        cast(str, doc["version"]),
        cast(str, doc["canonicalization"]),
        tuple(cast(list[str], doc["alert_invariants"])),
        *(
            cast(int, doc[key])
            for key in (
                "batch_rows",
                "batch_bytes",
                "cache_mib",
                "database_estimate_multiplier",
                "temporary_estimate_multiplier",
                "max_database_bytes",
                "minimum_free_bytes",
                "max_seconds",
            )
        ),
    )


def encoded(values: list[str]) -> str:
    """Exact decoded cells: no trimming, normalization, numeric casts or sorting."""
    return json.dumps(values, ensure_ascii=True, separators=(",", ":"))


def sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def peak_working_set() -> dict[str, object]:
    """OS cumulative process peak; SQLite is in-process, not a child service."""
    if sys.platform == "win32":
        import ctypes

        class Counters(ctypes.Structure):
            peak: int
            _fields_ = [
                ("cb", ctypes.c_ulong),
                ("faults", ctypes.c_ulong),
                *(
                    (name, ctypes.c_size_t)
                    for name in (
                        "peak",
                        "working",
                        "peak_paged",
                        "paged",
                        "peak_nonpaged",
                        "nonpaged",
                        "pagefile",
                        "peak_pagefile",
                    )
                ),
            ]

        counters = Counters()
        function = ctypes.WinDLL("psapi").GetProcessMemoryInfo
        function.argtypes = [ctypes.c_void_p, ctypes.POINTER(Counters), ctypes.c_ulong]
        function.restype = ctypes.c_int
        if function(
            ctypes.c_void_p(-1), ctypes.byref(counters), ctypes.sizeof(counters)
        ):
            return {
                "bytes": counters.peak,
                "method": "Windows PeakWorkingSetSize",
            }
    elif sys.platform.startswith("linux"):
        import resource

        return {
            "bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
            "method": "Linux ru_maxrss",
        }
    return {"bytes": None, "method": "not measured on this platform"}


def verify_output(
    output: Path, lock_path: Path, contract_path: Path, config_path: Path
) -> dict[str, object]:
    """Verify a full G3 bundle before accepting it; no CSV reads or reconstruction."""
    report = read_json(output / "report.json")
    if report.get("gate") != "G3" or report.get("status") != "PASSED":
        raise ReconstructionError("Only a full PASSED G3 bundle can be verified")
    identity = cast(dict[str, object], report["reconstruction_identity"])
    source = cast(dict[str, object], identity["source_identity"])
    lock = read_json(lock_path)
    statistics = cast(dict[str, object], report["statistics"])
    files = cast(dict[str, dict[str, int]], report["source_counts"])
    checks = cast(dict[str, bool], statistics["checks"])
    implementation = cast(dict[str, str], identity["implementation_sha256"])
    config = load_config(config_path)
    expected_modules = {
        "incidents.py",
        "incident_store.py",
        "incident_preflight.py",
        "reconstruct_guide.py",
        "acquisition.py",
        "schema.py",
        "schema_contract.py",
    }
    valid = (
        report.get("gate") == "G3"
        and report.get("status") == "PASSED"
        and report.get("training_allowed") is False
        and identity.get("benchmark_modulus") is None
        and report.get("failure") is None
        and source.get("files") == lock.get("files")
        and source.get("release_lock_sha256") == sha(lock_path)
        and identity.get("contract_sha256") == load_contract(contract_path).sha256
        and fingerprint(identity.get("configuration")) == fingerprint(asdict(config))
        and (
            config.version != "guide-v1-reconstruction-2"
            or identity.get("metadata_consistency_scope")
            == ["OrgId", "IncidentId", "AlertId"]
        )
        and report.get("reconstruction_sha256") == fingerprint(identity)
        and bool(checks)
        and all(value is True for value in checks.values())
        and statistics["input_evidence_rows"]
        == sum(c["scanned"] for c in files.values())
        and all(c["scanned"] == c["selected"] for c in files.values())
        and set(implementation) == expected_modules
    )
    if not valid:
        raise ReconstructionError(
            "Full G3 report identity/accounting verification failed"
        )
    for name, digest in implementation.items():
        if sha(Path(__file__).with_name(name)) != digest:
            raise ReconstructionError(
                "G3 implementation digest differs from this checkout"
            )
    database = cast(dict[str, object], report["database"])
    if (
        database["path"] != "incidents.sqlite3"
        or sha(output / "incidents.sqlite3") != database["sha256"]
    ):
        raise ReconstructionError("G3 database artifact digest mismatch")
    return {
        "status": "VERIFIED_G3_OUTPUT",
        "training_allowed": False,
        "reconstruction_sha256": report["reconstruction_sha256"],
    }


def reconstruct(
    files_root: Path,
    lock_path: Path,
    contract_path: Path,
    schema_report_path: Path,
    config_path: Path,
    output: Path,
    *,
    benchmark_modulus: int | None = None,
    progress: Callable[[str], None] = print,
) -> dict[str, object]:
    """Produce a fresh G3 bundle. Existing output and immutable inputs are never overwritten."""
    started = time.monotonic()
    config = load_config(config_path)
    if benchmark_modulus is not None and benchmark_modulus < 2:
        raise ReconstructionError("Benchmark modulus must be at least two")
    if output.exists() or output.resolve().is_relative_to(files_root.resolve()):
        raise ReconstructionError(
            "Choose a fresh output outside immutable source files"
        )
    # Shared G1 integrity code runs before any CSV read; no redownload or copies.
    progress("G1 source verification")
    identity = verify_files(files_root, lock_path)
    verification_seconds = time.monotonic() - started
    contract = load_contract(contract_path)
    g2 = read_json(schema_report_path)
    if (
        identity["version"] != contract.dataset_version
        or identity["acquisition_manifest_sha256"] != contract.source_manifest_sha256
        or g2.get("gate") != "G2"
        or g2.get("status") != "PASSED"
        or g2.get("source_identity") != identity
        or g2.get("contract_sha256") != contract.sha256
        or g2.get("source_metadata_unchanged") is not True
    ):
        raise ReconstructionError("G1/G2 identity, schema or full acceptance mismatch")
    g2_files = cast(list[dict[str, object]], g2.get("files", []))
    if {f["file"] for f in g2_files} != {f.name for f in contract.files} or any(
        not f.get("complete") or not all(cast(dict[str, bool], f["checks"]).values())
        for f in g2_files
    ):
        raise ReconstructionError("G2 report is incomplete or failed")
    expected_rows = {str(f["file"]): int(cast(int, f["rows"])) for f in g2_files}
    sources = [files_root / f.name for f in contract.files]
    before = {
        p.name: (p.stat().st_ino, p.stat().st_size, p.stat().st_mtime_ns)
        for p in sources
    }
    common = tuple(
        name
        for name in contract.files[0].header
        if all(name in f.header for f in contract.files)
    )
    if set(common) != set(contract.columns) - {"Usage"}:
        raise ReconstructionError("Unsupported common schema")
    output.mkdir(parents=True)
    temporary = output / "sqlite-temp"
    temporary.mkdir()
    database = output / "incidents.sqlite3"
    deadline = started + config.max_seconds
    maximum_artifact_bytes = 0
    maximum_temporary_bytes = 0
    last_guard = 0.0

    def guard() -> None:
        nonlocal maximum_artifact_bytes, maximum_temporary_bytes, last_guard
        now = time.monotonic()
        if now >= deadline:
            raise ResourceLimitError("time_limit")
        if now - last_guard >= 1:
            last_guard = now
            sizes = temporary_sizes = 0
            for path in output.rglob("*"):
                if path.is_file():
                    size = path.stat().st_size
                    sizes += size
                    if path.is_relative_to(temporary):
                        temporary_sizes += size
            maximum_artifact_bytes = max(maximum_artifact_bytes, sizes)
            maximum_temporary_bytes = max(maximum_temporary_bytes, temporary_sizes)
            if shutil.disk_usage(output).free < config.minimum_free_bytes:
                raise ResourceLimitError("free_disk_floor")

    counts: dict[str, dict[str, int]] = {}
    statistics: dict[str, object] | None = None
    preflight: dict[str, object] | None = None
    failure: str | None = None
    status = "BLOCKED"
    ingestion_seconds: float | None = None
    summarization_seconds: float | None = None
    connection = sqlite3.connect(database)
    old_temp = connection.execute("PRAGMA temp_store_directory").fetchone()
    old_temp_path = str(old_temp[0]) if old_temp else ""
    interrupted: list[str] = []

    def sql_guard() -> int:
        try:
            guard()
        except ResourceLimitError as error:
            interrupted[:] = [str(error)]
            return 1
        return 0

    try:
        guard()
        preflight = storage_preflight(
            files_root,
            output,
            source_bytes=sum(
                int(cast(int, f["bytes"]))
                for f in cast(list[dict[str, object]], identity["files"])
            ),
            database_multiplier=config.database_estimate_multiplier,
            temporary_multiplier=config.temporary_estimate_multiplier,
            max_database_bytes=config.max_database_bytes,
            minimum_free_bytes=config.minimum_free_bytes,
        )
        if preflight["status"] != "READY":
            raise ResourceLimitError("storage_preflight_failed")
        # temp_store_directory is connection-external SQLite state: G3 is a serial
        # command, never a concurrent application worker. Restore it in finally.
        quoted_temp = str(temporary.resolve()).replace("'", "''")
        connection.execute(f"PRAGMA temp_store_directory='{quoted_temp}'")
        actual_temp = connection.execute("PRAGMA temp_store_directory").fetchone()
        if actual_temp is None or actual_temp[0] != str(temporary.resolve()):
            raise ReconstructionError(
                "SQLite cannot place temporary files in configured output"
            )
        connection.execute("PRAGMA temp_store=FILE")
        connection.execute("PRAGMA mmap_size=0")
        connection.execute("PRAGMA threads=1")
        connection.execute(f"PRAGMA cache_size=-{config.cache_mib * 1024}")
        connection.execute("PRAGMA synchronous=NORMAL")
        connection.execute("PRAGMA journal_mode=DELETE")
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        connection.execute(
            f"PRAGMA max_page_count={max(1, config.max_database_bytes // page_size)}"
        )
        connection.set_progress_handler(sql_guard, 10000)
        connection.executescript(DDL)
        batch: list[tuple[object, ...]] = []
        batch_bytes = 0

        def flush() -> None:
            nonlocal batch_bytes
            guard()
            connection.executemany(
                "INSERT INTO evidence(org,incident,alert,grade,grade_state,source,usage,exact,content,invariant,payload) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                batch,
            )
            connection.commit()
            batch.clear()
            batch_bytes = 0

        parsing = ScanLimits()
        ingestion_started = time.monotonic()
        previous_limit = csv.field_size_limit(parsing.field_chars)
        try:
            for file in contract.files:
                scanned = selected = 0
                with (files_root / file.name).open(
                    encoding="utf-8", newline=""
                ) as stream:
                    lines = RecordLines(stream, parsing.record_chars)
                    reader = csv.reader(lines, strict=True)
                    if tuple(next(reader, list[str]())) != file.header:
                        raise ReconstructionError("Header differs from G2 contract")
                    indices = {name: file.header.index(name) for name in file.header}
                    common_indices = [indices[name] for name in common]
                    content_indices = [
                        i
                        for i, name in enumerate(common)
                        if name not in {"Id", "IncidentGrade"}
                    ]
                    invariant_indices = [
                        indices[name] for name in config.alert_invariants
                    ]
                    while True:
                        lines.consumed = 0
                        row = next(reader, None)
                        if row is None:
                            break
                        scanned += 1
                        if scanned % 2048 == 0:
                            guard()
                        if scanned % 500000 == 0:
                            progress(
                                f"{file.name}: {scanned:,} scanned, {selected:,} selected"
                            )
                        if len(row) != len(file.header):
                            raise ReconstructionError("Record width differs from G2")
                        org, incident, alert = (
                            row[indices[n]] for n in ("OrgId", "IncidentId", "AlertId")
                        )
                        if any(
                            not s or not s.isascii() or not s.isdigit()
                            for s in (org, incident, alert)
                        ):
                            raise ReconstructionError(
                                "Invalid required key; no row silently discarded"
                            )
                        if benchmark_modulus is not None:
                            key = hashlib.sha256(
                                encoded([org, incident]).encode()
                            ).digest()
                            if int.from_bytes(key[:8], "big") % benchmark_modulus:
                                continue
                        values = [row[i] for i in common_indices]
                        payload = encoded(values)
                        grade = row[indices["IncidentGrade"]]
                        grade_state = (
                            0
                            if not grade or grade.isspace()
                            else LABELS.index(grade) + 1
                            if grade in LABELS
                            else 4
                        )
                        usage = row[indices["Usage"]] if "Usage" in indices else ""
                        exact = hashlib.sha256(payload.encode()).digest()
                        content = hashlib.sha256(
                            encoded([values[i] for i in content_indices]).encode()
                        ).digest()
                        invariant = hashlib.sha256(
                            encoded([row[i] for i in invariant_indices]).encode()
                        ).digest()
                        cost = (
                            len(payload) * 2
                            + len(org + incident + alert + grade + usage) * 2
                            + 512
                        )
                        if cost > config.batch_bytes:
                            raise ResourceLimitError("single_record_batch_budget")
                        if batch and batch_bytes + cost > config.batch_bytes:
                            flush()
                        batch.append(
                            (
                                org,
                                incident,
                                alert,
                                grade,
                                grade_state,
                                file.name,
                                usage,
                                exact,
                                content,
                                invariant,
                                payload,
                            )
                        )
                        batch_bytes += cost
                        selected += 1
                        if len(batch) >= config.batch_rows:
                            flush()
                flush()
                counts[file.name] = {"scanned": scanned, "selected": selected}
                if scanned != expected_rows[file.name]:
                    raise ReconstructionError(
                        "Evidence row count differs from verified G2"
                    )
        finally:
            csv.field_size_limit(previous_limit)
        ingestion_seconds = time.monotonic() - ingestion_started
        summary_started = time.monotonic()
        statistics = summarize(
            connection,
            progress,
            incident_scoped=config.version == "guide-v1-reconstruction-2",
        )
        summarization_seconds = time.monotonic() - summary_started
        stable = all(
            before[p.name] == (p.stat().st_ino, p.stat().st_size, p.stat().st_mtime_ns)
            for p in sources
        )
        checks = cast(dict[str, bool], statistics["checks"])
        checks["sources_unchanged"] = stable
        checks["selected_rows_reconciled"] = statistics["input_evidence_rows"] == sum(
            c["selected"] for c in counts.values()
        )
        status = (
            "BLOCKED"
            if not all(checks.values())
            else "PARTIAL"
            if benchmark_modulus
            else "PASSED"
        )
    except ResourceLimitError as error:
        failure, status = str(error), "PARTIAL"
    except sqlite3.Error as error:
        failure = interrupted[0] if interrupted else type(error).__name__
        status = (
            "PARTIAL"
            if interrupted
            or getattr(error, "sqlite_errorcode", None) == sqlite3.SQLITE_FULL
            else "BLOCKED"
        )
    except (ReconstructionError, csv.Error, UnicodeError, ValueError) as error:
        failure = (
            str(error)
            if isinstance(error, ReconstructionError)
            else type(error).__name__
        )
    finally:
        connection.set_progress_handler(None, 0)
        connection.rollback()
        connection.execute(
            "PRAGMA temp_store_directory='" + old_temp_path.replace("'", "''") + "'"
        )
        connection.close()
    code = {
        name: sha(Path(__file__).with_name(name))
        for name in (
            "incidents.py",
            "incident_store.py",
            "incident_preflight.py",
            "reconstruct_guide.py",
            "acquisition.py",
            "schema.py",
            "schema_contract.py",
        )
    }
    reconstruction_identity = {
        "source_identity": identity,
        "contract_sha256": contract.sha256,
        "configuration": asdict(config),
        "implementation_sha256": code,
        "benchmark_modulus": benchmark_modulus,
        "logical_records_sha256": statistics.get("logical_records_sha256")
        if statistics
        else None,
    }
    if config.version == "guide-v1-reconstruction-2":
        reconstruction_identity["metadata_consistency_scope"] = [
            "OrgId",
            "IncidentId",
            "AlertId",
        ]
    artifact_bytes = sum(p.stat().st_size for p in output.rglob("*") if p.is_file())
    report: dict[str, object] = {
        "gate": "G3",
        "status": status,
        "training_allowed": False,
        "reconstruction_identity": reconstruction_identity,
        "reconstruction_sha256": fingerprint(reconstruction_identity),
        "g2_report_sha256": sha(schema_report_path),
        "source_counts": counts,
        "statistics": statistics,
        "resource_preflight": preflight,
        "failure": failure,
        "database": {
            "path": "incidents.sqlite3",
            "bytes": database.stat().st_size,
            "sha256": sha(database),
        },
        "duration_seconds": round(time.monotonic() - started, 6),
        "phase_seconds": {
            "verification": verification_seconds,
            "ingestion": ingestion_seconds,
            "summarization": summarization_seconds,
        },
        "artifact_bytes": artifact_bytes,
        "maximum_observed_artifact_bytes": max(artifact_bytes, maximum_artifact_bytes),
        "maximum_observed_temporary_file_bytes": maximum_temporary_bytes,
        "peak_memory": peak_working_set(),
        "sqlite_version": sqlite3.sqlite_version,
        "python_version": platform.python_version(),
        "operating_system": platform.system(),
        "common_columns": common,
        "warnings": [
            (
                "V2 metadata quarantine is incident-scoped; global alert variation/reuse remains diagnostic."
                if config.version == "guide-v1-reconstruction-2"
                else "V1 metadata quarantine is global across incidents sharing a scoped alert."
            ),
            "No feature provenance, dependency components, dataset splits or training performed.",
            "Original source files are provenance partitions, not Amyntor evaluation roles.",
            "Hash-selected benchmark runs are PARTIAL even when selected incidents are complete.",
            "SQLite physical layout and row representatives are not reconstruction identity.",
            "Alert metadata conflicts are conservatively quarantined, not silently resolved.",
            "Disk observation excludes OS-invisible/unlinked temporary files; free-space floor is also enforced.",
        ],
    }
    (output / "report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return report
