from __future__ import annotations

import csv
import hashlib
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import venv
from pathlib import Path
from typing import cast

import pytest

from amyntor.data.acquisition import AcquisitionError
from amyntor.data.incident_store import DDL, summarize
from amyntor.data.incidents import ReconstructionError, reconstruct, verify_output
from amyntor.data.schema import ScanLimits, validate_dataset

REPO = Path(__file__).resolve().parents[2]
Row = dict[str, str]


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object, **kwargs: object) -> None:
        pytest.fail("G3 tests must not access the network")

    monkeypatch.setattr(socket.socket, "connect", fail)


def row(**changes: str) -> Row:
    return {
        "OrgId": "01",
        "IncidentId": "02",
        "AlertId": "03",
        "Id": "04",
        "Timestamp": "2024-06-01T00:00:00Z",
        "Category": "Malware",
        "EntityType": "Device",
        "IncidentGrade": "TruePositive",
        **changes,
    }


def fixture_inputs(tmp: Path, train: list[Row], test: list[Row]) -> list[Path]:
    tmp.mkdir(parents=True, exist_ok=True)
    root = tmp / "mount"
    root.mkdir()
    schema = json.loads((REPO / "configs/guide-v1.schema.json").read_text())
    schema["source_manifest_sha256"] = "1" * 64
    contract = tmp / "schema.json"
    contract.write_text(json.dumps(schema))
    for spec in schema["files"]:
        selected = train if spec["name"] == "GUIDE_Train.csv" else test
        with (root / spec["name"]).open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow(spec["header"])
            for values in selected:
                defaults = {"OrgId": "01", "IncidentId": "02", "AlertId": "03"}
                writer.writerow(
                    [
                        values.get(name, defaults.get(name, ""))
                        for name in spec["header"]
                    ]
                )
    lock_doc = json.loads((REPO / "configs/guide-v1.lock.json").read_text())
    lock_doc["acquisition_manifest_sha256"] = "1" * 64
    lock_doc["files"] = [
        {
            "name": p.name,
            "bytes": p.stat().st_size,
            "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
        }
        for p in sorted(root.iterdir())
    ]
    lock = tmp / "lock.json"
    lock.write_text(json.dumps(lock_doc))
    g2 = tmp / "g2.json"
    report = validate_dataset(root, lock, contract, ScanLimits())
    assert report["status"] == "PASSED"
    g2.write_text(json.dumps(report))
    config = tmp / "config.json"
    cfg = json.loads((REPO / "configs/guide-v1.reconstruction.json").read_text())
    cfg["minimum_free_bytes"] = 1
    config.write_text(json.dumps(cfg))
    return [root, lock, contract, g2, config, tmp / "output"]


def stats(report: dict[str, object]) -> dict[str, object]:
    assert report["status"] == "PASSED"
    result = cast(dict[str, object], report["statistics"])
    assert all(cast(dict[str, bool], result["checks"]).values())
    return result


def quiet(message: str) -> None:
    pass


def test_complete_incidents_alerts_and_legitimate_entity_sets(tmp_path: Path) -> None:
    inputs = fixture_inputs(
        tmp_path,
        [row(DeviceId="001"), row(Id="05", DeviceId="002"), row(Id="06", AlertId="09")],
        [row(IncidentId="10", AlertId="11")],
    )
    report = reconstruct(*inputs, progress=quiet)
    result = stats(report)
    assert result["unique_incidents"] == 2
    assert result["unique_scoped_alerts"] == 3
    assert result["retained_labeled_incidents"] == 2
    assert result["conflicting_scoped_alerts"] == 0
    assert result["evidence_rows_per_incident_before_dedup"] == {
        "min": 1,
        "median": 2.0,
        "p95": 3,
        "max": 3,
    }
    with sqlite3.connect(inputs[-1] / "incidents.sqlite3") as connection:
        assert connection.execute(
            "SELECT org,incident FROM incidents ORDER BY incident"
        ).fetchall() == [("01", "02"), ("01", "10")]
        assert connection.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == 4


def test_duplicates_repetition_and_row_reconciliation(tmp_path: Path) -> None:
    inputs = fixture_inputs(tmp_path, [row(), row(), row(Id="05")], [row()])
    result = stats(reconstruct(*inputs, progress=quiet))
    assert result["input_evidence_rows"] == 4
    assert result["exact_unique_rows"] == 2
    assert result["exact_duplicate_rows"] == 2
    assert result["repeated_evidence_rows_ignoring_row_id"] == 3
    assert result["nonexact_repeated_evidence_rows"] == 1
    assert result["cross_source_incidents"] == 1
    assert result["cross_source_exact_records"] == 1
    reconciled = cast(dict[str, int], result["row_reconciliation"])
    assert reconciled == {
        "retained_unique": 2,
        "retained_duplicate_occurrences": 2,
        "quarantined_unique": 0,
        "quarantined_duplicate_occurrences": 0,
        "orphan_or_unparseable_rows": 0,
        "unexplained_loss": 0,
    }


@pytest.mark.parametrize("grade", ["", " \t", "\u00a0", "FalsePositive"])
def test_missing_or_conflicting_grade_quarantines_whole_cross_file_incident(
    grade: str,
    tmp_path: Path,
) -> None:
    inputs = fixture_inputs(
        tmp_path, [row(), row(Id="05", DeviceId="02")], [row(IncidentGrade=grade)]
    )
    result = stats(reconstruct(*inputs, progress=quiet))
    assert result["retained_labeled_incidents"] == 0
    assert result["quarantined_incidents"] == 1
    assert result["cross_source_quarantined_incidents"] == 1
    counts = cast(dict[str, dict[str, int]], result["quarantine_by_reason_overlapping"])
    assert (
        counts[
            "missing_grade"
            if grade.isspace() or not grade
            else "conflicting_known_grades"
        ]["input_rows"]
        == 3
    )
    with sqlite3.connect(inputs[-1] / "incidents.sqlite3") as connection:
        assert (
            connection.execute(
                "SELECT grade FROM evidence WHERE source='GUIDE_Test.csv'"
            ).fetchone()[0]
            == grade
        )


def test_missing_and_conflicting_reasons_do_not_double_count(tmp_path: Path) -> None:
    inputs = fixture_inputs(
        tmp_path,
        [row(), row(IncidentGrade=""), row(IncidentGrade="FalsePositive")],
        [row(IncidentId="10", AlertId="20")],
    )
    result = stats(reconstruct(*inputs, progress=quiet))
    assert result["quarantined_incidents"] == 1
    combinations = cast(
        list[dict[str, int]], result["quarantine_disjoint_reason_combinations"]
    )
    assert sum(c["input_rows"] for c in combinations) == 4
    assert any(c["reason_mask"] == 3 and c["input_rows"] == 3 for c in combinations)
    assert result["label_only_conflicting_evidence_groups"] == 1


@pytest.mark.parametrize("conflict", [False, True])
def test_alert_reuse_and_invariant_conflicts(conflict: bool, tmp_path: Path) -> None:
    inputs = fixture_inputs(
        tmp_path,
        [row()],
        [
            row(
                IncidentId="10",
                Category="Phishing" if conflict else "Malware",
                DeviceId="02",
            )
        ],
    )
    result = stats(reconstruct(*inputs, progress=quiet))
    assert result["reused_scoped_alerts"] == 1
    assert result["quarantined_incidents"] == (2 if conflict else 0)
    assert result["conflicting_scoped_alerts"] == int(conflict)


def test_leading_zero_identifiers_are_distinct_and_scoped(tmp_path: Path) -> None:
    inputs = fixture_inputs(
        tmp_path, [row(), row(OrgId="1"), row(IncidentId="2")], [row(AlertId="3")]
    )
    result = stats(reconstruct(*inputs, progress=quiet))
    assert result["unique_incidents"] == 3
    assert result["unique_scoped_alerts"] == 3
    assert result["reused_scoped_alerts"] == 1


def test_reordering_rows_preserves_logical_reconstruction(tmp_path: Path) -> None:
    train = [row(), row(), row(Id="05", DeviceId="02"), row(IncidentGrade="")]
    test = [row(IncidentId="10", AlertId="20"), row(IncidentGrade="FalsePositive")]
    left = fixture_inputs(tmp_path / "left", train, test)
    right = fixture_inputs(
        tmp_path / "right", list(reversed(train)), list(reversed(test))
    )
    a = stats(reconstruct(*left, progress=quiet))
    b = stats(reconstruct(*right, progress=quiet))
    assert a == b


def test_resource_limits_never_pass(tmp_path: Path) -> None:
    inputs = fixture_inputs(tmp_path, [row()], [row()])
    config = json.loads(inputs[4].read_text())
    config["max_database_bytes"] = 4096
    inputs[4].write_text(json.dumps(config))
    report = reconstruct(*inputs, progress=quiet)
    assert report["status"] == "PARTIAL"
    assert report["training_allowed"] is False


def test_disk_floor_fails_closed(tmp_path: Path) -> None:
    inputs = fixture_inputs(tmp_path, [row()], [row()])
    config = json.loads(inputs[4].read_text())
    config["minimum_free_bytes"] = 2**63
    inputs[4].write_text(json.dumps(config))
    report = reconstruct(*inputs, progress=quiet)
    assert report["status"] == "PARTIAL" and report["failure"] == "free_disk_floor"


def test_sources_must_be_unchanged_before_inspection(tmp_path: Path) -> None:
    inputs = fixture_inputs(tmp_path, [row()], [row()])
    (inputs[0] / "GUIDE_Train.csv").write_text("altered")
    with pytest.raises(AcquisitionError):
        reconstruct(*inputs, progress=quiet)
    assert not inputs[-1].exists()


@pytest.mark.parametrize("change", ["partial", "identity", "contract"])
def test_rejects_inconsistent_g2(change: str, tmp_path: Path) -> None:
    inputs = fixture_inputs(tmp_path, [row()], [row()])
    report = json.loads(inputs[3].read_text())
    if change == "partial":
        report["status"] = "PARTIAL"
    elif change == "identity":
        report["source_identity"]["version"] = 2
    else:
        report["contract_sha256"] = "0" * 64
    inputs[3].write_text(json.dumps(report))
    with pytest.raises(ReconstructionError):
        reconstruct(*inputs, progress=quiet)


def test_benchmark_is_complete_groups_but_never_a_full_pass(tmp_path: Path) -> None:
    train = [row(IncidentId=str(n), AlertId=str(n)) for n in range(30)]
    inputs = fixture_inputs(tmp_path, train, list(reversed(train)))
    report = reconstruct(*inputs, benchmark_modulus=3, progress=quiet)
    assert report["status"] == "PARTIAL"
    with sqlite3.connect(inputs[-1] / "incidents.sqlite3") as connection:
        assert connection.execute(
            "SELECT DISTINCT source_count,input_rows FROM incidents"
        ).fetchall() == [(2, 2)]


def test_unknown_grades_remain_distinguishable_in_disk_accounting() -> None:
    with sqlite3.connect(":memory:") as connection:
        connection.executescript(DDL)
        connection.execute(
            "INSERT INTO evidence VALUES(1,'01','02','03','UnknownRaw',4,'source','',?,?,?,?)",
            (b"a", b"b", b"c", "[raw]"),
        )
        result = summarize(connection, quiet)
        assert result["quarantined_incidents"] == 1
        assert result["retained_labeled_incidents"] == 0
        assert (
            cast(dict[str, dict[str, int]], result["quarantine_by_reason_overlapping"])[
                "unknown_grade"
            ]["incidents"]
            == 1
        )


def test_output_cannot_overwrite_inputs_or_prior_artifacts(tmp_path: Path) -> None:
    inputs = fixture_inputs(tmp_path, [row()], [row()])
    inputs[-1] = inputs[0] / "output"
    with pytest.raises(ReconstructionError):
        reconstruct(*inputs, progress=quiet)


@pytest.mark.parametrize(
    "field,value",
    [
        ("Timestamp", "2024-06-02T00:00:00Z"),
        ("DetectorId", "other-detector"),
        ("AlertTitle", "other-title"),
        ("Category", "Phishing"),
    ],
)
def test_each_declared_alert_invariant_is_enforced(
    field: str, value: str, tmp_path: Path
) -> None:
    inputs = fixture_inputs(tmp_path, [row()], [row(**{field: value})])
    result = stats(reconstruct(*inputs, progress=quiet))
    assert result["conflicting_scoped_alerts"] == 1
    assert result["retained_labeled_incidents"] == 0


def test_legitimate_platform_values_are_not_alert_invariants(tmp_path: Path) -> None:
    inputs = fixture_inputs(
        tmp_path,
        [row(OSFamily="01", OSVersion="02")],
        [row(OSFamily="1", OSVersion="2", EntityType="Account")],
    )
    result = stats(reconstruct(*inputs, progress=quiet))
    assert result["exact_unique_rows"] == 2
    assert result["quarantined_incidents"] == 0


def test_time_limit_never_produces_a_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = fixture_inputs(tmp_path, [row()], [row()])
    ticks = iter([0.0, 10000.0])
    monkeypatch.setattr(
        "amyntor.data.incidents.time.monotonic", lambda: next(ticks, 10000.0)
    )
    report = reconstruct(*inputs, progress=quiet)
    assert report["status"] == "PARTIAL" and report["failure"] == "time_limit"


def test_single_row_batch_budget_is_enforced(tmp_path: Path) -> None:
    inputs = fixture_inputs(tmp_path, [row()], [row()])
    config = json.loads(inputs[4].read_text())
    config["batch_bytes"] = 1
    inputs[4].write_text(json.dumps(config))
    report = reconstruct(*inputs, progress=quiet)
    assert report["status"] == "PARTIAL"
    assert report["failure"] == "single_record_batch_budget"


def test_full_fixture_artifact_verification_and_corruption_detection(
    tmp_path: Path,
) -> None:
    inputs = fixture_inputs(tmp_path, [row()], [row()])
    reconstruct(*inputs, progress=quiet)
    output, lock, contract, config = inputs[-1], inputs[1], inputs[2], inputs[4]
    result = verify_output(output, lock, contract, config)
    assert result["status"] == "VERIFIED_G3_OUTPUT"
    assert result["training_allowed"] is False
    with (output / "incidents.sqlite3").open("ab") as stream:
        stream.write(b"changed")
    with pytest.raises(ReconstructionError, match="artifact digest"):
        verify_output(output, lock, contract, config)


def test_partial_artifacts_cannot_be_verified_as_complete(tmp_path: Path) -> None:
    inputs = fixture_inputs(tmp_path, [row()], [row()])
    reconstruct(*inputs, benchmark_modulus=3, progress=quiet)
    with pytest.raises(ReconstructionError, match="full PASSED"):
        verify_output(inputs[-1], inputs[1], inputs[2], inputs[4])


def test_source_only_kaggle_entry_point_with_synthetic_files(tmp_path: Path) -> None:
    inputs = fixture_inputs(
        tmp_path / "fixtures",
        [row(), row(), row(Id="05", DeviceId="002")],
        [row(IncidentId="10", AlertId="20")],
    )
    # Add unrelated mount content after producing the original two-file G2 report.
    (inputs[0] / "GUIDE_Test_Queue_Rankings.csv").write_bytes(b"\x00not evidence CSV")
    repo = tmp_path / "source-only tree"
    shutil.copytree(
        REPO / "src", repo / "src", ignore=shutil.ignore_patterns("__pycache__")
    )
    (repo / "scripts").mkdir()
    shutil.copyfile(
        REPO / "scripts/run_guide_g3_kaggle.py",
        repo / "scripts/run_guide_g3_kaggle.py",
    )
    (repo / "configs").mkdir()
    for source, name in zip(
        (inputs[1], inputs[2], inputs[4]),
        ("guide-v1.lock.json", "guide-v1.schema.json", "guide-v1.reconstruction.json"),
        strict=True,
    ):
        # These trust pins describe synthetic fixtures, never production GUIDE.
        shutil.copyfile(source, repo / "configs" / name)
    runtime = tmp_path / "empty-runtime"
    venv.EnvBuilder(with_pip=False).create(runtime)
    python = runtime / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    probe = subprocess.run(
        [
            str(python),
            "-c",
            """
from importlib.metadata import PackageNotFoundError, version
try:
    version('amyntor')
except PackageNotFoundError:
    pass
else:
    raise AssertionError('Runner test requires no installed Amyntor distribution')
""",
        ],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert probe.returncode == 0, probe.stdout + probe.stderr
    command = [
        str(python),
        str(repo / "scripts/run_guide_g3_kaggle.py"),
        "--files-root",
        str(inputs[0]),
        "--schema-report",
        str(inputs[3]),
        "--output",
        str(inputs[-1]),
    ]
    for flags, expected in (
        (["--preflight-only"], '"status": "READY"'),
        ([], "G3 PASSED"),
        (["--verify-output"], "VERIFIED_G3_OUTPUT"),
    ):
        result = subprocess.run(
            [*command, *flags],
            cwd=tmp_path,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert expected in result.stdout
        if flags == ["--preflight-only"]:
            assert not inputs[-1].exists()
    report = json.loads((inputs[-1] / "report.json").read_text())
    assert report["training_allowed"] is False
    assert report["statistics"]["input_evidence_rows"] == 4
    assert report["statistics"]["unique_incidents"] == 2
    assert report["statistics"]["exact_duplicate_rows"] == 1
    assert set(report["source_counts"]) == {"GUIDE_Train.csv", "GUIDE_Test.csv"}
    assert (
        report["database"]["bytes"] == (inputs[-1] / "incidents.sqlite3").stat().st_size
    )
    assert report["maximum_observed_temporary_file_bytes"] >= 0

    benchmark = tmp_path / "benchmark-output"
    benchmark_command = [*command[:-1], str(benchmark), "--benchmark-modulus", "3"]
    result = subprocess.run(
        benchmark_command,
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    benchmark_report = json.loads((benchmark / "report.json").read_text())
    assert benchmark_report["status"] == "PARTIAL"
    assert benchmark_report["training_allowed"] is False
    assert benchmark_report["failure"] is None
    assert benchmark_report["reconstruction_identity"]["benchmark_modulus"] == 3
    assert all(benchmark_report["statistics"]["checks"].values())
    refused = subprocess.run(
        [*benchmark_command, "--verify-output"],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert refused.returncode == 2
