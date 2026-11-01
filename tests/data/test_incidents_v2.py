from __future__ import annotations

import json
import os
import socket
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import cast

import pytest

from amyntor.data.incident_store import DDL, summarize
from amyntor.data.incidents import ReconstructionError, reconstruct, verify_output
from tests.data.test_incidents import REPO, Row, fixture_inputs, quiet, row, stats


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object, **kwargs: object) -> None:
        pytest.fail("G3 v2 tests must not access the network")

    monkeypatch.setattr(socket.socket, "connect", fail)


def inputs_v2(tmp: Path, train: list[Row], test: list[Row]) -> list[Path]:
    inputs = fixture_inputs(tmp, train, test)
    config = json.loads((REPO / "configs/guide-v1.reconstruction-v2.json").read_text())
    config["minimum_free_bytes"] = 1
    inputs[4].write_text(json.dumps(config))
    return inputs


def test_cross_incident_timestamp_variation_is_diagnostic_only(tmp_path: Path) -> None:
    inputs = inputs_v2(
        tmp_path,
        [row(), row(), row(DeviceId="002")],
        [
            row(
                IncidentId="002",
                Timestamp="2024-06-02T00:00:00Z",
                IncidentGrade="FalsePositive",
            )
        ],
    )
    report = reconstruct(*inputs, progress=quiet)
    result = stats(report)
    assert result["unique_incidents"] == 2
    assert result["unique_scoped_alerts"] == 1
    assert result["unique_incident_alerts"] == 2
    assert result["retained_labeled_incidents"] == 2
    assert result["quarantined_incidents"] == 0
    assert result["conflicting_scoped_alerts"] == 1  # global variation remains visible
    assert result["conflicting_incident_alerts"] == 0
    assert result["reused_scoped_alerts"] == 1
    assert result["cross_source_scoped_alerts"] == 1
    assert result["cross_incident_cross_source_scoped_alerts"] == 1
    assert result["exact_duplicate_rows"] == 1
    assert result["retained_incident_labels"] == {"FalsePositive": 1, "TruePositive": 1}
    assert sum(cast(dict[str, int], result["row_reconciliation"]).values()) == 4
    identity = cast(dict[str, object], report["reconstruction_identity"])
    assert identity["metadata_consistency_scope"] == ["OrgId", "IncidentId", "AlertId"]
    assert report["training_allowed"] is False
    assert (
        verify_output(inputs[-1], inputs[1], inputs[2], inputs[4])["status"]
        == "VERIFIED_G3_OUTPUT"
    )
    with sqlite3.connect(inputs[-1] / "incidents.sqlite3") as connection:
        assert connection.execute(
            "SELECT incident FROM incident_alert_metadata ORDER BY incident"
        ).fetchall() == [("002",), ("02",)]
        assert connection.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == 4


@pytest.mark.parametrize(
    "field,value",
    [
        ("Timestamp", "2024-06-02T00:00:00Z"),
        ("DetectorId", "10"),
        ("AlertTitle", "20"),
        ("Category", "Phishing"),
    ],
)
def test_each_invariant_enforced_within_incident_across_files(
    field: str, value: str, tmp_path: Path
) -> None:
    inputs = inputs_v2(tmp_path, [row(), row(AlertId="99")], [row(**{field: value})])
    result = stats(reconstruct(*inputs, progress=quiet))
    assert result["conflicting_incident_alerts"] == 1
    assert result["cross_source_incident_alerts"] == 1
    assert result["quarantined_incidents"] == 1
    assert result["retained_labeled_incidents"] == 0
    reasons = cast(
        dict[str, dict[str, int]], result["quarantine_by_reason_overlapping"]
    )
    assert reasons["conflicting_alert_metadata"] == {"incidents": 1, "input_rows": 3}


@pytest.mark.parametrize("second,quarantined", [("", 0), ("2024-06-01T00:00:00Z", 1)])
def test_nullable_metadata_is_compared_without_filling(
    second: str, quarantined: int, tmp_path: Path
) -> None:
    inputs = inputs_v2(tmp_path, [row(Timestamp="")], [row(Timestamp=second)])
    result = stats(reconstruct(*inputs, progress=quiet))
    assert result["quarantined_incidents"] == quarantined


def test_repetition_label_quarantine_and_order_invariance(tmp_path: Path) -> None:
    train = [
        row(),
        row(),
        row(DeviceId="002"),
        row(IncidentId="4", AlertId="4", IncidentGrade=""),
        row(IncidentId="5", AlertId="5"),
    ]
    test = [
        row(IncidentId="6", Timestamp="2024-06-02T00:00:00Z"),
        row(IncidentId="5", AlertId="5", IncidentGrade="FalsePositive"),
    ]
    left = inputs_v2(tmp_path / "left", train, test)
    right = inputs_v2(tmp_path / "right", list(reversed(train)), list(reversed(test)))
    a = stats(reconstruct(*left, progress=quiet))
    b = stats(reconstruct(*right, progress=quiet))
    assert a == b
    assert a["unique_incidents"] == 4
    assert a["retained_labeled_incidents"] == 2
    assert a["quarantined_incidents"] == 2
    assert a["exact_duplicate_rows"] == 1
    assert a["input_evidence_rows"] == 7
    reasons = cast(dict[str, dict[str, int]], a["quarantine_by_reason_overlapping"])
    assert reasons["missing_grade"]["incidents"] == 1
    assert reasons["conflicting_known_grades"]["incidents"] == 1
    assert reasons["conflicting_alert_metadata"]["incidents"] == 0
    assert sum(cast(dict[str, int], a["row_reconciliation"]).values()) == 7


def test_unknown_grade_never_recovered_by_v2_scope() -> None:
    with sqlite3.connect(":memory:") as connection:
        connection.executescript(DDL)
        connection.execute(
            "INSERT INTO evidence VALUES (1,'01','02','03','Unknown',4,'source','',?,?,?,?)",
            (b"a", b"b", b"c", "[]"),
        )
        result = summarize(connection, quiet, incident_scoped=True)
        assert result["retained_labeled_incidents"] == 0
        assert result["quarantined_incidents"] == 1
        assert (
            cast(dict[str, dict[str, int]], result["quarantine_by_reason_overlapping"])[
                "unknown_grade"
            ]["incidents"]
            == 1
        )


def test_versions_cannot_share_acceptance_identity(tmp_path: Path) -> None:
    train = [row()]
    test = [row(IncidentId="9", Timestamp="2024-06-02T00:00:00Z")]
    old = fixture_inputs(tmp_path / "v1", train, test)
    new = inputs_v2(tmp_path / "v2", train, test)
    old_report = reconstruct(*old, progress=quiet)
    original_database = (old[-1] / "incidents.sqlite3").read_bytes()
    original_report = (old[-1] / "report.json").read_bytes()
    new_report = reconstruct(*new, progress=quiet)
    assert stats(old_report)["retained_labeled_incidents"] == 0
    assert stats(new_report)["retained_labeled_incidents"] == 2
    assert (
        stats(old_report)["logical_records_sha256"]
        == stats(new_report)["logical_records_sha256"]
    )
    assert old_report["reconstruction_sha256"] != new_report["reconstruction_sha256"]
    for inputs, config in ((old, new[4]), (new, old[4])):
        with pytest.raises(ReconstructionError, match="identity/accounting"):
            verify_output(inputs[-1], inputs[1], inputs[2], config)
    assert (old[-1] / "incidents.sqlite3").read_bytes() == original_database
    assert (old[-1] / "report.json").read_bytes() == original_report


def test_thin_kaggle_runner_v2_with_synthetic_files(tmp_path: Path) -> None:
    inputs = inputs_v2(
        tmp_path, [row()], [row(IncidentId="9", Timestamp="2024-06-02T00:00:00Z")]
    )
    command = [
        sys.executable,
        str(REPO / "scripts/run_guide_g3_kaggle.py"),
        "--files-root",
        str(inputs[0]),
        "--schema-report",
        str(inputs[3]),
        "--config",
        str(inputs[4]),
        "--output",
        str(inputs[-1]),
    ]
    # Relocate the actual thin runner with synthetic pins instead of production pins.
    import shutil

    copy = tmp_path / "source"
    shutil.copytree(
        REPO / "src", copy / "src", ignore=shutil.ignore_patterns("__pycache__")
    )
    (copy / "scripts").mkdir()
    shutil.copyfile(
        REPO / "scripts/run_guide_g3_kaggle.py", copy / "scripts/run_guide_g3_kaggle.py"
    )
    (copy / "configs").mkdir()
    shutil.copyfile(inputs[1], copy / "configs/guide-v1.lock.json")
    shutil.copyfile(inputs[2], copy / "configs/guide-v1.schema.json")
    command[1] = str(copy / "scripts/run_guide_g3_kaggle.py")
    for flags in (["--preflight-only"], [], ["--verify-output"]):
        completed = subprocess.run(
            [*command, *flags],
            env={**os.environ, "PYTHONPATH": ""},
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert completed.returncode == 0, completed.stdout + completed.stderr
    report = json.loads((inputs[-1] / "report.json").read_text())
    assert report["statistics"]["retained_labeled_incidents"] == 2
    assert (
        report["reconstruction_identity"]["configuration"]["version"]
        == "guide-v1-reconstruction-2"
    )
