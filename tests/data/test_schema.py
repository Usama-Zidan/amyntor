from __future__ import annotations

import csv
import hashlib
import json
import socket
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from amyntor.data.acquisition import AcquisitionError
from amyntor.data.schema import ScanLimits, validate_dataset
from amyntor.data.schema_contract import SchemaError, load_contract
from amyntor.data.validate_guide import main

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def blocked(*args: object, **kwargs: object) -> None:
        pytest.fail("Schema tests must be network independent")

    monkeypatch.setattr(socket.socket, "connect", blocked)


@pytest.fixture
def inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    root = tmp_path / "opaque-mount"
    root.mkdir()
    document: dict[str, object] = json.loads(
        (REPO / "configs/guide-v1.schema.json").read_text()
    )
    document["source_manifest_sha256"] = "1" * 64
    contract_path = tmp_path / "schema.json"
    contract_path.write_text(json.dumps(document), encoding="utf-8")
    contract = load_contract(contract_path)
    for file in contract.files:
        rows: list[list[str]] = []
        for label in ("TruePositive", "BenignPositive", "FalsePositive"):
            row: list[str] = []
            for name in file.header:
                column = contract.columns[name]
                kind = column.representation
                value = (
                    "0009007199254740993"
                    if kind == "unsigned_integer_string"
                    else "2024-06-01T00:00:00Z"
                    if kind == "timestamp"
                    else "Context"
                    if kind == "categorical_text"
                    else column.allowed_values[0]
                    if column.allowed_values
                    else "opaque-value"
                )
                row.append(label if name == "IncidentGrade" else value)
            rows.append(row)
        with (root / file.name).open("w", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(file.header)
            writer.writerows(rows)
    lock = tmp_path / "source.lock.json"
    original: dict[str, object] = json.loads(
        (REPO / "configs/guide-v1.lock.json").read_text()
    )
    original["acquisition_manifest_sha256"] = "1" * 64
    lock.write_text(json.dumps(original), encoding="utf-8")
    refresh_lock(root, lock)
    return root, lock, contract_path


def refresh_lock(root: Path, lock: Path) -> None:
    """Synthetic fixtures only; never derive production trust pins from inputs."""
    document: dict[str, object] = json.loads(lock.read_text())
    document["files"] = [
        {
            "name": path.name,
            "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for path in sorted(root.iterdir())
    ]
    lock.write_text(json.dumps(document), encoding="utf-8")


def rewrite_train(
    inputs: tuple[Path, Path, Path], change: Callable[[list[list[str]]], None]
) -> None:
    root, lock, _ = inputs
    path = root / "GUIDE_Train.csv"
    with path.open(encoding="utf-8", newline="") as stream:
        rows = list(csv.reader(stream))  # Tiny synthetic fixture, never corpus data.
    change(rows)
    with path.open("w", encoding="utf-8", newline="") as stream:
        csv.writer(stream).writerows(rows)
    refresh_lock(root, lock)


def run(
    inputs: tuple[Path, Path, Path], limits: ScanLimits | None = None
) -> dict[str, object]:
    return validate_dataset(*inputs, limits or ScanLimits())


def train_report(report: dict[str, object]) -> dict[str, object]:
    return next(
        item
        for item in cast(list[dict[str, object]], report["files"])
        if item["file"] == "GUIDE_Train.csv"
    )


def column(report: dict[str, object], name: str) -> dict[str, object]:
    return next(
        item
        for item in cast(list[dict[str, object]], train_report(report)["columns"])
        if item["name"] == name
    )


def test_valid_release_contract_and_roles(inputs: tuple[Path, Path, Path]) -> None:
    report = run(inputs)
    assert report["status"] == "PASSED" and report["training_allowed"] is False
    for file in cast(list[dict[str, object]], report["files"]):
        assert file["rows"] == 3 and file["row_count_exact"] is True
        assert all(cast(dict[str, bool], file["checks"]).values())
    assert column(report, "OSVersion")["model_status"] == "UNRESOLVED"
    assert column(report, "IncidentId")["representation"] == "unsigned_integer_string"
    assert "0009007199254740993" not in json.dumps(report)
    comparison = cast(dict[str, object], report["schema_comparison"])
    assert comparison["file_specific_columns"] == {
        "GUIDE_Test.csv": ["Usage"],
        "GUIDE_Train.csv": [],
    }


def test_unrelated_mounted_file_does_not_change_g2_identity_or_schema(
    inputs: tuple[Path, Path, Path],
) -> None:
    original = run(inputs)
    (inputs[0] / "GUIDE_Test_Queue_Rankings.csv").write_bytes(b"\x00not evidence CSV")
    observed = run(inputs)
    assert observed["status"] == "PASSED"
    assert observed["source_identity"] == original["source_identity"]
    assert observed["files"] == original["files"]


@pytest.mark.parametrize(
    "mutation", ["missing_required", "duplicate", "empty", "unexpected"]
)
def test_header_failures(mutation: str, inputs: tuple[Path, Path, Path]) -> None:
    def change(rows: list[list[str]]) -> None:
        if mutation == "missing_required":
            index = rows[0].index("OrgId")
            for row in rows:
                row.pop(index)
        elif mutation == "duplicate":
            rows[0][-1] = "OrgId"
        elif mutation == "empty":
            rows[0][-1] = ""
        else:
            for row in rows:
                row.append("NewColumn" if row is rows[0] else "private-data")

    rewrite_train(inputs, change)
    report = run(inputs)
    assert report["status"] == "BLOCKED"
    assert train_report(report)["rows"] == 3
    assert "private-data" not in json.dumps(report)


def test_missing_labels_remain_missing_and_rows_are_not_removed(
    inputs: tuple[Path, Path, Path],
) -> None:
    def change(rows: list[list[str]]) -> None:
        rows[1][rows[0].index("IncidentGrade")] = ""

    rewrite_train(inputs, change)
    report = run(inputs)
    target = cast(dict[str, object], train_report(report)["target"])
    assert report["status"] == "PASSED"
    assert target["missing_empty"] == 1 and target["usable_labeled_rows"] == 2
    assert train_report(report)["rows"] == 3
    assert "NOT incidents" in cast(str, target["unit"])


@pytest.mark.parametrize(
    "name,value",
    [
        ("IncidentGrade", "invented-secret-label"),
        ("OrgId", "1.0"),
        ("OSVersion", "1e4"),
        ("Category", '["Malware"]'),
        ("Timestamp", "2024-06-01"),
    ],
)
def test_incompatible_values_are_counted_not_coerced(
    name: str, value: str, inputs: tuple[Path, Path, Path]
) -> None:
    def change(rows: list[list[str]]) -> None:
        rows[1][rows[0].index(name)] = value

    rewrite_train(inputs, change)
    report = run(inputs)
    assert report["status"] == "BLOCKED"
    assert column(report, name)["incompatible_nonempty"] == 1
    assert value not in json.dumps(report)


def test_missingness_tokens_are_not_silently_merged(
    inputs: tuple[Path, Path, Path],
) -> None:
    def change(rows: list[list[str]]) -> None:
        for name, value in {
            "DeviceId": "0",
            "ThreatFamily": "None",
            "Roles": " \t",
            "ResourceType": "",
        }.items():
            rows[1][rows[0].index(name)] = value

    rewrite_train(inputs, change)
    report = run(inputs)
    assert report["status"] == "PASSED"
    assert (
        cast(dict[str, int], column(report, "DeviceId")["literal_sentinel_probes"])["0"]
        == 1
    )
    assert column(report, "DeviceId")["empty"] == 0
    assert (
        cast(
            dict[str, int], column(report, "ThreatFamily")["literal_null_like_tokens"]
        )["None"]
        == 1
    )
    assert column(report, "Roles")["whitespace_only"] == 1
    assert column(report, "ResourceType")["empty"] == 1


def test_malformed_csv_blocks_and_stops_without_resynchronization(
    inputs: tuple[Path, Path, Path],
) -> None:
    root, lock, _ = inputs
    path = root / "GUIDE_Train.csv"
    header = path.read_text().splitlines()[0]
    path.write_text(header + '\n"unterminated\n', encoding="utf-8")
    refresh_lock(root, lock)
    report = run(inputs)
    assert report["status"] == "BLOCKED"
    assert train_report(report)["malformed_csv_errors"] == 1
    assert train_report(report)["row_count_exact"] is False


def test_wrong_width_is_explicit(inputs: tuple[Path, Path, Path]) -> None:
    def change(rows: list[list[str]]) -> None:
        rows[1].pop()

    rewrite_train(inputs, change)
    report = run(inputs)
    assert report["status"] == "BLOCKED"
    assert train_report(report)["wrong_width_records"] == 1
    assert train_report(report)["valid_width_rows"] == 2


def test_integrity_precedes_csv_inspection(
    inputs: tuple[Path, Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _, _ = inputs
    (root / "GUIDE_Train.csv").write_bytes(b"changed")

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("Must not inspect unverified source")

    monkeypatch.setattr("amyntor.data.schema.scan_csv", forbidden)
    with pytest.raises(AcquisitionError):
        run(inputs)


def test_source_contract_mismatch(inputs: tuple[Path, Path, Path]) -> None:
    _, _, path = inputs
    document: dict[str, object] = json.loads(path.read_text())
    document["dataset_version"] = 2
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(SchemaError, match="identity"):
        run(inputs)


def test_no_predictor_approval_at_g2(inputs: tuple[Path, Path, Path]) -> None:
    _, _, path = inputs
    document: dict[str, object] = json.loads(path.read_text())
    columns = cast(list[dict[str, object]], document["columns"])
    next(col for col in columns if col["name"] == "Category")["model_status"] = (
        "ACCEPTED"
    )
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(SchemaError, match="approve"):
        run(inputs)


def test_statistics_deterministic_and_portable(
    inputs: tuple[Path, Path, Path], tmp_path: Path
) -> None:
    first = run(inputs)
    root, lock, contract = inputs
    moved = tmp_path / "relocated-mount"
    root.rename(moved)
    second = run((moved, lock, contract))
    first.pop("duration_seconds")
    second.pop("duration_seconds")
    assert first == second
    assert str(tmp_path) not in json.dumps(second)


def test_partial_scans_never_pass(inputs: tuple[Path, Path, Path]) -> None:
    report = run(inputs, ScanLimits(max_rows_per_file=1))
    assert report["status"] == "PARTIAL"
    assert all(
        not item["row_count_exact"]
        for item in cast(list[dict[str, object]], report["files"])
    )


@pytest.mark.parametrize(
    "limit", [ScanLimits(field_chars=10), ScanLimits(record_chars=20)]
)
def test_bounded_csv_records_do_not_claim_completion(
    limit: ScanLimits, inputs: tuple[Path, Path, Path]
) -> None:
    report = run(inputs, limit)
    assert report["status"] != "PASSED"
    assert any(
        item["resource_stop"] is not None
        for item in cast(list[dict[str, object]], report["files"])
    )


def test_distinct_values_are_bounded_lower_bounds(
    inputs: tuple[Path, Path, Path],
) -> None:
    report = run(inputs, ScanLimits(distinct_values=1))
    assert column(report, "IncidentGrade")["distinct_nonempty"] == {
        "kind": "lower_bound",
        "value": 2,
    }


def test_cli_report_and_input_protection(
    inputs: tuple[Path, Path, Path], tmp_path: Path
) -> None:
    root, lock, contract = inputs
    output = tmp_path / "reports/schema.json"
    args = ["--files-root", str(root), "--lock", str(lock), "--contract", str(contract)]
    assert main([*args, "--output", str(output)]) == 0
    report: dict[str, object] = json.loads(output.read_text())
    assert report["status"] == "PASSED"
    assert main([*args, "--output", str(root / "report.json")]) == 2


def test_batch_boundaries_preserve_exact_statistics(
    inputs: tuple[Path, Path, Path],
) -> None:
    ordinary = run(inputs)
    small_batches = run(inputs, ScanLimits(batch_rows=2, batch_values=2))
    assert ordinary["files"] == small_batches["files"]


def test_literal_null_label_is_not_silently_imputed(
    inputs: tuple[Path, Path, Path],
) -> None:
    def change(rows: list[list[str]]) -> None:
        rows[1][rows[0].index("IncidentGrade")] = "None"

    rewrite_train(inputs, change)
    report = run(inputs)
    assert report["status"] == "BLOCKED"
    target = cast(dict[str, object], train_report(report)["target"])
    assert target["unexpected"] == 1 and target["missing_empty"] == 0


def test_missing_identifier_is_blocking(inputs: tuple[Path, Path, Path]) -> None:
    def change(rows: list[list[str]]) -> None:
        rows[1][rows[0].index("OrgId")] = ""

    rewrite_train(inputs, change)
    report = run(inputs)
    assert report["status"] == "BLOCKED"
    assert train_report(report)["required_missing_cells"] == 1


@pytest.mark.parametrize("kind", ["field", "multiline_record"])
def test_resource_bounds_apply_to_body_after_valid_header(
    kind: str, inputs: tuple[Path, Path, Path]
) -> None:
    value = "x" * 129 if kind == "field" else "\n".join(["x" * 100] * 20)

    def change(rows: list[list[str]]) -> None:
        rows[1][rows[0].index("Roles")] = value

    rewrite_train(inputs, change)
    limits = (
        ScanLimits(field_chars=128)
        if kind == "field"
        else ScanLimits(record_chars=1024)
    )
    report = run(inputs, limits)
    file = train_report(report)
    assert report["status"] == "PARTIAL"
    assert file["column_count"] == 45 and file["row_count_exact"] is False
    assert file["resource_stop"] == (
        "field_character_limit" if kind == "field" else "record_character_limit"
    )
    assert value not in json.dumps(report)
