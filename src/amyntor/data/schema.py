"""G2 only: streaming evidence-row schema statistics, without incident state."""

from __future__ import annotations

import csv
import hashlib
import platform
import re
import time
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TextIO, cast

from amyntor.data.acquisition import verify_files
from amyntor.data.schema_contract import (
    LABELS,
    REQUIRED_IDS,
    ColumnContract,
    FileContract,
    SchemaContract,
    SchemaError,
    fingerprint,
    load_contract,
)

DECIMAL = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\Z")
CATEGORY = re.compile(r"[A-Za-z][A-Za-z0-9_ ./:-]*\Z")
HEADER_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}\Z")


@dataclass(frozen=True)
class ScanLimits:
    field_chars: int = 65536
    record_chars: int = 1048576
    columns: int = 128
    distinct_values: int = 128
    retained_value_chars: int = 128
    batch_rows: int = 2048
    batch_values: int = 128
    max_seconds: int = 3600
    max_rows_per_file: int | None = None

    def __post_init__(self) -> None:
        if any(
            value <= 0
            for value in (
                self.field_chars,
                self.record_chars,
                self.columns,
                self.distinct_values,
                self.retained_value_chars,
                self.batch_rows,
                self.batch_values,
                self.max_seconds,
            )
        ):
            raise SchemaError("Scan limits must be positive")
        if self.max_rows_per_file is not None and self.max_rows_per_file <= 0:
            raise SchemaError("Row limit must be positive")


class RecordLimitError(ValueError):
    """One CSV record exceeded its configured character budget."""


@dataclass
class RecordLines(Iterator[str]):
    stream: TextIO
    maximum: int
    consumed: int = 0

    def __next__(self) -> str:
        line = self.stream.readline(self.maximum - self.consumed + 1)
        if not line:
            raise StopIteration
        self.consumed += len(line)
        if self.consumed > self.maximum:
            raise RecordLimitError
        return line


@dataclass
class ColumnStats:
    empty: int = 0
    whitespace_only: int = 0
    null_like: Counter[str] = field(default_factory=Counter[str])
    sentinel_probes: Counter[str] = field(default_factory=Counter[str])
    unsigned_integer_strings: int = 0
    decimal_like_strings: int = 0
    other_strings: int = 0
    incompatible: int = 0
    max_chars: int = 0
    enum_counts: Counter[str] = field(default_factory=Counter[str])
    unexpected_enum: int = 0
    distinct: set[str] = field(default_factory=set[str])
    distinct_floor: int | None = None

    def observe(
        self,
        value: str,
        spec: ColumnContract | None,
        contract: SchemaContract,
        limits: ScanLimits,
        multiplicity: int = 1,
    ) -> None:
        if not value:
            self.empty += multiplicity
            return
        if value.isspace():
            self.whitespace_only += multiplicity
            return
        self.max_chars = max(self.max_chars, len(value))
        if value in contract.null_tokens:
            self.null_like[value] += multiplicity
        if value in contract.sentinel_tokens:
            self.sentinel_probes[value] += multiplicity
        if self.distinct_floor is None:
            if len(value) > limits.retained_value_chars:
                self.distinct_floor = len(self.distinct) + 1
                self.distinct.clear()
            else:
                self.distinct.add(value)
                if len(self.distinct) > limits.distinct_values:
                    self.distinct_floor = len(self.distinct)
                    self.distinct.clear()
        unsigned = value.isascii() and value.isdigit()
        decimal = False
        if unsigned:
            self.unsigned_integer_strings += multiplicity
        elif DECIMAL.fullmatch(value):
            decimal = True
            self.decimal_like_strings += multiplicity
        else:
            self.other_strings += multiplicity
        if spec is None:
            return
        incompatible = "\x00" in value
        kind = spec.representation
        if kind == "unsigned_integer_string":
            incompatible |= not unsigned
        elif kind == "categorical_text":
            incompatible |= unsigned or decimal or CATEGORY.fullmatch(value) is None
        elif kind == "enum_string":
            if value in spec.allowed_values:
                self.enum_counts[value] += multiplicity
            else:
                self.unexpected_enum += multiplicity
                incompatible = True
        elif kind == "timestamp":
            try:
                parsed = datetime.fromisoformat(value)
                incompatible |= "T" not in value or parsed.tzinfo is None
            except ValueError:
                incompatible = True
        self.incompatible += int(incompatible) * multiplicity

    def report(
        self, spec: ColumnContract | None, contract: SchemaContract
    ) -> dict[str, object]:
        return {
            "role": spec.role if spec else "UNREVIEWED",
            "model_status": spec.model_status if spec else "EXCLUDED",
            "representation": spec.representation if spec else "unreviewed_string",
            "empty": self.empty,
            "whitespace_only": self.whitespace_only,
            "literal_null_like_tokens": {
                v: self.null_like[v] for v in contract.null_tokens
            },
            "literal_sentinel_probes": {
                v: self.sentinel_probes[v] for v in contract.sentinel_tokens
            },
            "lexical_types": {
                "unsigned_integer_string": self.unsigned_integer_strings,
                "decimal_like_string": self.decimal_like_strings,
                "other_string": self.other_strings,
            },
            "incompatible_nonempty": self.incompatible,
            "max_chars": self.max_chars,
            "distinct_nonempty": {
                "kind": "exact" if self.distinct_floor is None else "lower_bound",
                "value": len(self.distinct)
                if self.distinct_floor is None
                else self.distinct_floor,
            },
            "allowed_enum_counts": {v: self.enum_counts[v] for v in spec.allowed_values}
            if spec
            else {},
            "unexpected_enum_count": self.unexpected_enum,
        }


def scan_csv(
    path: Path,
    file_contract: FileContract,
    contract: SchemaContract,
    limits: ScanLimits,
    *,
    deadline: float,
    progress: Callable[[str, int], None] | None = None,
) -> dict[str, object]:
    """Scan one file independently. Any lost record boundary stops that file."""
    header: list[str] = []
    statistics: list[ColumnStats] = []
    specs: list[ColumnContract | None] = []
    pending: list[Counter[str]] = []

    def flush_column(index: int) -> None:
        for value, count in pending[index].items():
            statistics[index].observe(value, specs[index], contract, limits, count)
        pending[index].clear()

    def flush_all() -> None:
        for index in range(len(pending)):
            flush_column(index)

    rows = 0
    valid_width = 0
    widths: Counter[int] = Counter[int]()
    parser_errors = 0
    encoding_errors = 0
    resource_stop: str | None = None
    complete = False
    previous_field_limit = csv.field_size_limit(limits.field_chars)
    try:
        with path.open("r", encoding="utf-8", errors="strict", newline="") as stream:
            lines = RecordLines(stream, limits.record_chars)
            reader = csv.reader(lines, strict=True)
            header = next(reader, None) or []
            if len(header) > limits.columns:
                resource_stop = "column_limit"
            else:
                statistics = [ColumnStats() for _ in header]
                specs = [contract.columns.get(name) for name in header]
                pending = [Counter[str]() for _ in header]
                while True:
                    if rows % 1024 == 0 and time.monotonic() >= deadline:
                        resource_stop = "time_limit"
                        break
                    if (
                        limits.max_rows_per_file is not None
                        and rows >= limits.max_rows_per_file
                    ):
                        resource_stop = "configured_row_limit"
                        break
                    lines.consumed = 0
                    row = next(reader, None)
                    if row is None:
                        complete = True
                        break
                    rows += 1
                    if len(row) != len(header):
                        widths[min(len(row), limits.columns + 1)] += 1
                    else:
                        valid_width += 1
                        for index, value in enumerate(row):
                            if len(value) > limits.retained_value_chars:
                                statistics[index].observe(
                                    value, specs[index], contract, limits
                                )
                            else:
                                pending[index][value] += 1
                                if len(pending[index]) >= limits.batch_values:
                                    flush_column(index)
                        if valid_width % limits.batch_rows == 0:
                            flush_all()
                    if progress and rows % 250000 == 0:
                        progress(path.name, rows)
    except RecordLimitError:
        resource_stop = "record_character_limit"
    except csv.Error as error:
        if "field larger than field limit" in str(error):
            resource_stop = "field_character_limit"
        else:
            parser_errors = 1
    except UnicodeError:
        encoding_errors = 1
    finally:
        csv.field_size_limit(previous_field_limit)
        flush_all()
    counts = Counter(header)

    def safe(name: str) -> str:
        return name if HEADER_NAME.fullmatch(name) else "<invalid_column_name>"

    missing_required = sorted((REQUIRED_IDS | {"IncidentGrade"}) - set(header))
    missing_expected = sorted(set(file_contract.header) - set(header))
    unexpected = sorted(set(header) - set(file_contract.header))
    required_missing = sum(
        stats.empty + stats.whitespace_only
        for name, stats in zip(header, statistics, strict=False)
        if name in REQUIRED_IDS
    )
    columns = [
        dict(
            name=safe(name),
            position=i,
            **stats.report(contract.columns.get(name), contract),
        )
        for i, (name, stats) in enumerate(zip(header, statistics, strict=False))
    ]
    target_index = (
        header.index("IncidentGrade")
        if "IncidentGrade" in header and statistics
        else None
    )
    target = statistics[target_index] if target_index is not None else ColumnStats()
    target_counts = {label: target.enum_counts[label] for label in LABELS}
    checks = {
        "nonempty_header": bool(header),
        "nonempty_data_if_complete": rows > 0 or not complete,
        "unique_nonempty_column_names": not any(
            not name or count > 1 for name, count in counts.items()
        ),
        "required_columns_present": not missing_required,
        "expected_header_and_order": tuple(header) == file_contract.header,
        "all_columns_reviewed": not unexpected
        and all(name in contract.columns for name in header),
        "csv_parse_clean": parser_errors == 0 and encoding_errors == 0,
        "consistent_widths": not widths,
        "required_identifiers_nonempty": required_missing == 0,
        "representations_compatible": all(
            stats.incompatible == 0 for stats in statistics
        ),
        "known_nonempty_labels": target.unexpected_enum == 0,
    }
    return {
        "file": path.name,
        "source_partition_role": file_contract.role,
        "header": [safe(name) for name in header],
        "column_count": len(header),
        "schema_fingerprint": fingerprint(header),
        "rows": rows,
        "row_count_exact": complete,
        "complete": complete,
        "valid_width_rows": valid_width,
        "wrong_width_records": sum(widths.values()),
        "wrong_width_histogram": dict(sorted(widths.items())),
        "column_statistics_scope": "Successfully parsed records with expected header width; no rows modified or removed",
        "duplicate_headers": {safe(name): n for name, n in counts.items() if n > 1},
        "empty_column_names": counts[""],
        "missing_required": missing_required,
        "missing_expected": missing_expected,
        "unexpected_columns": [safe(name) for name in unexpected],
        "malformed_csv_errors": parser_errors,
        "encoding_errors": encoding_errors,
        "resource_stop": resource_stop,
        "required_missing_cells": required_missing,
        "columns": columns,
        "checks": checks,
        "target": {
            "counts": target_counts,
            "missing_empty": target.empty,
            "missing_whitespace": target.whitespace_only,
            "unexpected": target.unexpected_enum,
            "usable_labeled_rows": sum(target_counts.values()),
            "has_usable_ground_truth": sum(target_counts.values()) > 0
            and target.unexpected_enum == 0,
            "unit": "evidence rows, NOT incidents",
        },
    }


def validate_dataset(
    files_root: Path,
    lock_path: Path,
    contract_path: Path,
    limits: ScanLimits,
    *,
    progress: Callable[[str, int], None] | None = None,
) -> dict[str, object]:
    started = time.monotonic()
    implementation = {
        name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
        for name in (
            "schema.py",
            "schema_contract.py",
            "validate_guide.py",
            "acquisition.py",
        )
    }
    # Integrity verification precedes every CSV read. No parallel implementation.
    identity = verify_files(files_root, lock_path)
    contract = load_contract(contract_path)
    records = cast(list[dict[str, object]], identity["files"])
    if (
        identity["version"] != contract.dataset_version
        or identity["acquisition_manifest_sha256"] != contract.source_manifest_sha256
        or {r["name"] for r in records} != {f.name for f in contract.files}
    ):
        raise SchemaError("Verified source identity does not match the G2 contract")
    paths = [files_root / f.name for f in contract.files]
    before = {
        p.name: (p.stat().st_ino, p.stat().st_size, p.stat().st_mtime_ns) for p in paths
    }
    deadline = started + limits.max_seconds
    reports = [
        scan_csv(
            files_root / f.name,
            f,
            contract,
            limits,
            deadline=deadline,
            progress=progress,
        )
        for f in contract.files
    ]
    stable = all(
        before[p.name] == (p.stat().st_ino, p.stat().st_size, p.stat().st_mtime_ns)
        for p in paths
    )
    clean = stable and all(
        all(cast(dict[str, bool], report["checks"]).values()) for report in reports
    )
    complete = all(report["complete"] for report in reports)
    status = "BLOCKED" if not clean else "PASSED" if complete else "PARTIAL"
    headers = {
        cast(str, report["file"]): tuple(cast(list[str], report["header"]))
        for report in reports
    }
    first_header = next(iter(headers.values()))
    common = set(first_header).intersection(
        *(set(header) for header in headers.values())
    )
    return {
        "report_version": 1,
        "gate": "G2",
        "status": status,
        "training_allowed": False,
        "source_identity": identity,
        "source_metadata_unchanged": stable,
        "contract_sha256": contract.sha256,
        "validator_sources_sha256": implementation,
        "python_version": platform.python_version(),
        "operating_system": platform.system(),
        "data_contract": contract.document,
        "files": reports,
        "schema_comparison": {
            "identical_headers": len(set(headers.values())) == 1,
            "file_specific_columns": {
                name: sorted(set(header) - common) for name, header in headers.items()
            },
            "basis": "Actual observed headers; release-specific differences reviewed in contract",
        },
        "limits": asdict(limits),
        "duration_seconds": round(time.monotonic() - started, 6),
        "peak_memory": "not measured; payload/record/cardinality memory bounded by configured limits",
        "warnings": [
            "All distributions are evidence-row counts, not incident class distributions.",
            "Empty labels remain empty. G3 must quarantine affected whole incidents; no reconstruction performed here.",
            "Null-like and sentinel-probe tokens are literal counts, not confirmed semantic NULLs. No imputation or coercion.",
            "Distinct counts are exact only until the cap; lower bounds are explicitly labeled. No raw value samples are emitted.",
            "All candidate model inputs remain UNRESOLVED; G2 approves no predictors.",
            "Usage is reviewed test-only metadata with unestablished publisher semantics; excluded from predictors and split decisions.",
        ],
        "unresolved_questions": [
            "Encoded placeholder/missing-value codebook",
            "Meaning of Usage",
            "Point-in-time availability of candidate fields",
            "Incident-level label consistency (G3)",
        ],
    }
