from __future__ import annotations

import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import cast

import pytest

from amyntor.data.incidents import (
    ReconstructionError,
    ResourceLimitError,
    encoded,
    reconstruct,
    sha,
)
from amyntor.data.quarantine_audit import audit
from tests.data.test_incidents import REPO, fixture_inputs, quiet, row


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object, **kwargs: object) -> None:
        pytest.fail("Audit tests must not access the network")

    monkeypatch.setattr(socket.socket, "connect", fail)


def execute(inputs: list[Path], scratch: Path) -> dict[str, object]:
    return audit(inputs[-1], inputs[1], inputs[2], scratch, minimum_free_bytes=1)


def scope(report: dict[str, object], modulus: int = 1) -> dict[str, object]:
    assert report["status"] == "COMPLETE"
    return cast(dict[str, dict[str, object]], report["scopes"])[str(modulus)]


def test_fields_scopes_counterfactual_labels_and_source_immutability(
    tmp_path: Path,
) -> None:
    inputs = fixture_inputs(
        tmp_path,
        [
            row(),
            row(),
            row(IncidentId="003", AlertId="004", AlertTitle="1"),
            row(IncidentId="003", AlertId="004", AlertTitle="2", Category="Phishing"),
            row(IncidentId="005", AlertId="006", IncidentGrade=""),
        ],
        [
            row(
                IncidentId="007",
                Timestamp="2024-06-02T00:00:00Z",
                IncidentGrade="FalsePositive",
            )
        ],
    )
    reconstruct(*inputs, progress=quiet)
    original_report = (inputs[-1] / "report.json").read_bytes()
    original_database = sha(inputs[-1] / "incidents.sqlite3")
    report = execute(inputs, tmp_path / "audit")
    full = scope(report)
    fields = cast(dict[str, dict[str, int]], full["field_counts"])
    assert fields["Timestamp"] == {
        "conflicting_alerts": 1,
        "across_incidents_only_alerts": 1,
        "across_sources_only_alerts": 1,
        "affected_incidents": 2,
        "rows_on_affected_incidents": 3,
    }
    assert fields["DetectorId"]["conflicting_alerts"] == 0
    assert fields["AlertTitle"]["conflicting_alerts"] == 1
    assert fields["Category"]["across_incidents_only_alerts"] == 0
    combinations = cast(list[dict[str, object]], full["alert_combinations"])
    assert {c["mask"] for c in combinations} == {0, 1, 12}
    assert sum(cast(int, c["evidence_rows_on_these_alerts"]) for c in combinations) == 6
    scenarios = cast(dict[str, dict[str, object]], full["scenarios"])
    assert scenarios["current_global_four"]["retained"] == 0
    for name in ("global_without_timestamp", "within_incident_four"):
        assert scenarios[name]["retained"] == 2
        assert scenarios[name]["retained_incident_labels"] == {
            "FalsePositive": 1,
            "TruePositive": 1,
        }
    assert scenarios["no_metadata_quarantine_upper_bound"]["retained"] == 3
    assert sha(inputs[-1] / "incidents.sqlite3") == original_database
    assert (inputs[-1] / "report.json").read_bytes() == original_report
    assert all(cast(dict[str, bool], report["checks"]).values())
    text = json.dumps(report)
    assert "2024-06-02T00:00:00Z" not in text
    assert '"007"' not in text
    # The attachment is read-only at the SQLite layer, even though scratch is writable.
    with sqlite3.connect(":memory:", uri=True) as connection:
        connection.execute(
            "ATTACH DATABASE ? AS src",
            ((inputs[-1] / "incidents.sqlite3").as_uri() + "?mode=ro",),
        )
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            connection.execute("DELETE FROM src.evidence")


def test_nested_sampling_exposes_missing_global_context(tmp_path: Path) -> None:
    buckets = {
        str(n): int.from_bytes(
            hashlib.sha256(encoded(["01", str(n)]).encode()).digest()[:8], "big"
        )
        for n in range(1000)
    }
    small = next(key for key, value in buckets.items() if value % 100 == 0)
    medium = next(
        key for key, value in buckets.items() if value % 10 == 0 and value % 100 != 0
    )
    large = next(key for key, value in buckets.items() if value % 10 != 0)
    inputs = fixture_inputs(
        tmp_path,
        [row(IncidentId=small), row(IncidentId=medium)],
        [row(IncidentId=large, Category="Phishing")],
    )
    reconstruct(*inputs, progress=quiet)
    report = execute(inputs, tmp_path / "audit")
    for modulus, count in ((100, 1), (10, 2), (1, 3)):
        result = scope(report, modulus)
        scenarios = cast(dict[str, dict[str, int]], result["scenarios"])
        assert scenarios["current_global_four"]["incidents"] == count
        assert scenarios["current_global_four"]["quarantined"] == (
            3 if modulus == 1 else 0
        )
        context = cast(
            dict[str, int], result["full_context_on_same_selected_incidents"]
        )
        assert context["metadata_conflict_incidents"] == count
        assert context["metadata_conflicts_invisible_in_subset"] == (
            0 if modulus == 1 else count
        )


@pytest.mark.parametrize("change", ["database", "report", "partial", "columns"])
def test_changed_or_incomplete_g3_rejected(change: str, tmp_path: Path) -> None:
    inputs = fixture_inputs(tmp_path, [row()], [row()])
    reconstruct(*inputs, progress=quiet)
    if change == "database":
        with (inputs[-1] / "incidents.sqlite3").open("ab") as stream:
            stream.write(b"changed")
    else:
        path = inputs[-1] / "report.json"
        doc = json.loads(path.read_text())
        if change == "partial":
            doc["status"] = "PARTIAL"
        elif change == "columns":
            doc["common_columns"] = list(reversed(doc["common_columns"]))
        else:
            doc["reconstruction_sha256"] = "0" * 64
        path.write_text(json.dumps(doc))
    with pytest.raises(ReconstructionError):
        execute(inputs, tmp_path / "audit")


def test_preflight_resource_limit_and_no_overwrite(tmp_path: Path) -> None:
    inputs = fixture_inputs(tmp_path, [row()], [row()])
    reconstruct(*inputs, progress=quiet)
    report = audit(
        inputs[-1],
        inputs[1],
        inputs[2],
        tmp_path / "audit",
        preflight_only=True,
        minimum_free_bytes=2**63,
    )
    assert report["source_verified"] is False
    assert cast(dict[str, object], report["preflight"])["feasible"] is False
    assert not (tmp_path / "audit").exists()
    with pytest.raises(ResourceLimitError):
        audit(
            inputs[-1],
            inputs[1],
            inputs[2],
            tmp_path / "audit",
            minimum_free_bytes=2**63,
        )
    with pytest.raises(ReconstructionError, match="fresh"):
        execute(inputs, inputs[-1] / "nested")


def test_counterfactuals_preserve_label_quarantine_and_compare_benchmarks(
    tmp_path: Path,
) -> None:
    inputs = fixture_inputs(
        tmp_path,
        [
            row(),
            row(IncidentGrade="FalsePositive"),
            row(IncidentId="7", AlertId="8", IncidentGrade=""),
        ],
        [row(IncidentId="9", AlertId="10")],
    )
    reconstruct(*inputs, progress=quiet)
    paths: list[Path] = []
    for modulus in (10, 100):
        destination = tmp_path / f"benchmark-{modulus}"
        reconstruct(
            inputs[0],
            inputs[1],
            inputs[2],
            inputs[3],
            inputs[4],
            destination,
            benchmark_modulus=modulus,
            progress=quiet,
        )
        paths.append(destination / "report.json")
    report = audit(
        inputs[-1],
        inputs[1],
        inputs[2],
        tmp_path / "audit",
        minimum_free_bytes=1,
        benchmark_reports=tuple(paths),
    )
    scenarios = cast(dict[str, dict[str, object]], scope(report)["scenarios"])
    assert all(s["retained"] == 1 for s in scenarios.values())
    assert scenarios["no_metadata_quarantine_upper_bound"][
        "retained_incident_labels"
    ] == {"TruePositive": 1}
    comparisons = cast(list[dict[str, object]], report["benchmark_reports"])
    assert all(c["matching_identity_except_sampling"] for c in comparisons)
    assert all(c["replay_matches_incident_and_quarantine_counts"] for c in comparisons)


def test_source_only_kaggle_command_and_order_invariance(tmp_path: Path) -> None:
    rows = [row(), row(IncidentId="3", Timestamp="2024-06-02T00:00:00Z")]
    left = fixture_inputs(tmp_path / "left", rows, [row(IncidentId="99", AlertId="99")])
    right = fixture_inputs(
        tmp_path / "right", list(reversed(rows)), [row(IncidentId="99", AlertId="99")]
    )
    reconstruct(*left, progress=quiet)
    reconstruct(*right, progress=quiet)
    expected = execute(left, tmp_path / "audit-left")
    output = tmp_path / "report.json"
    command = [
        sys.executable,
        "-S",
        "-m",
        "amyntor.data.quarantine_audit",
        "--g3-output",
        str(right[-1]),
        "--lock",
        str(right[1]),
        "--contract",
        str(right[2]),
        "--scratch",
        str(tmp_path / "audit-right"),
        "--report",
        str(output),
        "--minimum-free-bytes",
        "1",
    ]
    result = subprocess.run(
        command,
        env={**os.environ, "PYTHONPATH": str(REPO / "src")},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    observed = json.loads(output.read_text())
    assert observed["scopes"] == expected["scopes"]
