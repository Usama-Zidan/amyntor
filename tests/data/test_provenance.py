from __future__ import annotations

import json
import os
import socket
import sqlite3
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from amyntor.data.incidents import reconstruct, sha
from amyntor.data.provenance import COUNT, ProvenanceError, load_provenance
from amyntor.data.provenance_validation import ValidationLimits, validate_g4
from amyntor.data.schema_contract import load_contract
from amyntor.features.incident_snapshot import Evidence, project_snapshot
from tests.data.test_incidents import REPO, quiet, row
from tests.data.test_incidents_v2 import inputs_v2


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object, **kwargs: object) -> None:
        pytest.fail("G4 tests must not access the network")

    monkeypatch.setattr(socket.socket, "connect", fail)


def fixture(tmp: Path) -> tuple[list[Path], Path]:
    inputs = inputs_v2(
        tmp,
        [
            row(),
            row(),
            row(EntityType="Account"),
            row(AlertId="09", Category="Phishing"),
        ],
        [
            row(IncidentId="10", Timestamp="2024-06-02T00:00:00Z"),
            row(IncidentId="11", AlertId="15", IncidentGrade=""),
        ],
    )
    report = reconstruct(*inputs, progress=quiet)
    manifest = json.loads(
        (REPO / "configs/guide-v1.provenance.json").read_text(encoding="utf-8")
    )
    manifest["source_contract_sha256"] = load_contract(inputs[2]).sha256
    manifest["g3"] = {
        "reconstruction_sha256": report["reconstruction_sha256"],
        "report_sha256": sha(inputs[-1] / "report.json"),
        "database_sha256": sha(inputs[-1] / "incidents.sqlite3"),
        "database_bytes": (inputs[-1] / "incidents.sqlite3").stat().st_size,
    }
    path = tmp / "provenance.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return inputs, path


def execute(inputs: list[Path], path: Path, scratch: Path) -> dict[str, object]:
    return validate_g4(
        inputs[-1],
        inputs[1],
        inputs[2],
        path,
        scratch,
        limits=replace(ValidationLimits(), minimum_free_bytes=1),
        progress=quiet,
    )


def test_manifest_decisions_roles_and_minimum() -> None:
    contract = load_provenance(
        REPO / "configs/guide-v1.provenance.json", REPO / "configs/guide-v1.schema.json"
    )
    assert contract.ready
    assert contract.accepted == ("Category", "EntityType", COUNT)
    assert len(contract.fields) == 49
    assert all(
        contract.fields[n].status == "EXCLUDED"
        for n in (
            "OSFamily",
            "OSVersion",
            "ResourceType",
            "AntispamDirection",
            "IncidentGrade",
            "OrgId",
            "LastVerdict",
            "Timestamp",
            "source_partition",
        )
    )


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "duplicate",
        "unknown",
        "accepted_target",
        "evidence",
        "nulls",
        "order",
        "scope",
        "role",
        "hash",
    ],
)
def test_invalid_manifest_rejected(change: str, tmp_path: Path) -> None:
    doc = json.loads(
        (REPO / "configs/guide-v1.provenance.json").read_text(encoding="utf-8")
    )
    if change == "missing":
        doc["fields"].pop()
    elif change == "duplicate":
        doc["fields"].append(doc["fields"][0])
    elif change == "unknown":
        doc["fields"][0]["name"] = "Unlisted"
    elif change == "accepted_target":
        next(v for v in doc["fields"] if v["name"] == "IncidentGrade")["status"] = (
            "ACCEPTED"
        )
    elif change == "evidence":
        doc["fields"][0]["source_references"] = []
    elif change == "nulls":
        next(v for v in doc["fields"] if v["name"] == "Category")["null_rule"] = (
            "guess-zero-is-null"
        )
    elif change == "order":
        doc["accepted_fields"].reverse()
    elif change == "scope":
        doc["scope"] = "real-time"
    elif change == "role":
        doc["fields"][0]["role"] = "candidate_input"
    else:
        doc["g3"]["database_sha256"] = "invalid"
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(doc))
    with pytest.raises(ProvenanceError):
        load_provenance(path, REPO / "configs/guide-v1.schema.json")


def test_sql_validation_counts_isolation_and_pure_projection_agree(
    tmp_path: Path,
) -> None:
    inputs, path = fixture(tmp_path)
    original = {
        p: sha(p)
        for p in (inputs[-1] / "report.json", inputs[-1] / "incidents.sqlite3")
    }
    report = execute(inputs, path, tmp_path / "scratch")
    assert report["status"] == "PASSED"
    assert report["training_allowed"] is False and report["g5_g8_performed"] is False
    assert all(cast(dict[str, bool], report["checks"]).values())
    stats = cast(dict[str, object], report["statistics"])
    assert stats["retained_evidence_rows"] == 5
    assert stats["projected_incidents"] == 2
    assert stats["incident_local_alerts"] == 3
    contract = load_provenance(path, inputs[2])
    with sqlite3.connect(
        tmp_path / "scratch/projection.sqlite3", uri=True
    ) as connection:
        for incident, pure_rows in (
            (
                "02",
                [
                    Evidence(
                        "01",
                        "02",
                        "03",
                        {"Category": "Malware", "EntityType": "Device"},
                    ),
                    Evidence(
                        "01",
                        "02",
                        "03",
                        {"Category": "Malware", "EntityType": "Account"},
                    ),
                    Evidence(
                        "01",
                        "02",
                        "09",
                        {"Category": "Phishing", "EntityType": "Device"},
                    ),
                ],
            ),
            (
                "10",
                [
                    Evidence(
                        "01",
                        "10",
                        "03",
                        {"Category": "Malware", "EntityType": "Device"},
                    )
                ],
            ),
        ):
            pure = project_snapshot(pure_rows, contract)
            projected = connection.execute(
                "SELECT f.field,f.value,1.0*f.numerator/i.alerts FROM feature_counts f JOIN incident_counts i USING(org,incident) WHERE f.incident=? ORDER BY field,value",
                (incident,),
            ).fetchall()
            expected = sorted(
                (field, value.value, value.fraction)
                for field, values in pure.categorical.items()
                for value in values
            )
            assert projected == expected
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            connection.execute(
                "ATTACH DATABASE ? AS input_ro",
                ((inputs[-1] / "incidents.sqlite3").as_uri() + "?mode=ro",),
            )
            connection.execute("DELETE FROM input_ro.alerts")
    assert all(sha(p) == digest for p, digest in original.items())
    assert '"01"' not in json.dumps(report)
    assert '"Malware"' not in json.dumps(report)


@pytest.mark.parametrize("what", ["report", "database", "columns", "partial"])
def test_wrong_artifact_fails_closed(what: str, tmp_path: Path) -> None:
    inputs, path = fixture(tmp_path)
    if what == "database":
        with (inputs[-1] / "incidents.sqlite3").open("ab") as stream:
            stream.write(b"altered")
    else:
        target = inputs[-1] / "report.json"
        doc = json.loads(target.read_text())
        if what == "partial":
            doc["status"] = "PARTIAL"
        elif what == "columns":
            doc["common_columns"].reverse()
        else:
            doc["training_allowed"] = True
        target.write_text(json.dumps(doc))
        if what in ("columns", "partial"):
            pins = json.loads(path.read_text())
            pins["g3"]["report_sha256"] = sha(target)
            path.write_text(json.dumps(pins))
    with pytest.raises(ValueError):
        execute(inputs, path, tmp_path / "scratch")


def test_unresolved_and_excluded_minimum_never_pass(tmp_path: Path) -> None:
    inputs, path = fixture(tmp_path)
    doc = json.loads(path.read_text())
    next(d for d in doc["fields"] if d["name"] == "OSVersion")["status"] = "UNRESOLVED"
    path.write_text(json.dumps(doc))
    report = execute(inputs, path, tmp_path / "scratch")
    assert report["status"] == "BLOCKED" and not (tmp_path / "scratch").exists()
    contract = load_provenance(path, inputs[2])
    with pytest.raises(ProvenanceError):
        project_snapshot([], contract)


def test_preflight_partial_and_resource_failures(tmp_path: Path) -> None:
    inputs, path = fixture(tmp_path)
    limits = replace(ValidationLimits(), minimum_free_bytes=2**63)
    result = validate_g4(
        inputs[-1],
        inputs[1],
        inputs[2],
        path,
        tmp_path / "preflight",
        limits=limits,
        preflight_only=True,
    )
    assert result["source_verified"] is False
    assert cast(dict[str, object], result["preflight"])["feasible"] is False
    assert not (tmp_path / "preflight").exists()
    result = validate_g4(
        inputs[-1],
        inputs[1],
        inputs[2],
        path,
        tmp_path / "partial",
        limits=replace(limits, minimum_free_bytes=1),
        max_evidence_rows=1,
        progress=quiet,
    )
    assert result["status"] == "INCOMPLETE"
    result = validate_g4(
        inputs[-1],
        inputs[1],
        inputs[2],
        path,
        tmp_path / "tiny",
        limits=replace(limits, minimum_free_bytes=1, batch_bytes=1),
        progress=quiet,
    )
    assert (
        result["status"] == "INCOMPLETE"
        and result["failure"] == "single_projection_record_limit"
    )


def test_portable_source_only_command(tmp_path: Path) -> None:
    inputs, path = fixture(tmp_path)
    output = tmp_path / "g4.json"
    command = [
        sys.executable,
        "-S",
        "-m",
        "amyntor.data.validate_g4",
        "--g3-output",
        str(inputs[-1]),
        "--lock",
        str(inputs[1]),
        "--schema",
        str(inputs[2]),
        "--manifest",
        str(path),
        "--scratch",
        str(tmp_path / "scratch"),
        "--report",
        str(output),
        "--minimum-free-bytes",
        "1",
    ]
    for extra in (["--preflight-only"], []):
        result = subprocess.run(
            [*command, *extra],
            env={**os.environ, "PYTHONPATH": str(REPO / "src")},
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(output.read_text())["status"] == "PASSED"


def test_even_a_generous_explicit_row_limit_is_not_full_acceptance(
    tmp_path: Path,
) -> None:
    inputs, path = fixture(tmp_path)
    result = validate_g4(
        inputs[-1],
        inputs[1],
        inputs[2],
        path,
        tmp_path / "limited",
        limits=replace(ValidationLimits(), minimum_free_bytes=1),
        max_evidence_rows=1000,
        progress=quiet,
    )
    assert result["status"] == "INCOMPLETE"


def test_missing_minimum_and_time_limits_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs, path = fixture(tmp_path)
    ticks = iter([0.0])
    monkeypatch.setattr(
        "amyntor.data.provenance_validation.time.monotonic",
        lambda: next(ticks, 10000.0),
    )
    result = execute(inputs, path, tmp_path / "timeout")
    assert result["status"] == "INCOMPLETE" and result["failure"] == "time_limit"
    doc = json.loads(path.read_text())
    next(v for v in doc["fields"] if v["name"] == "Category")["status"] = "EXCLUDED"
    doc["accepted_fields"].remove("Category")
    path.write_text(json.dumps(doc))
    result = execute(inputs, path, tmp_path / "missing-minimum")
    assert result["status"] == "BLOCKED" and not (tmp_path / "missing-minimum").exists()


def test_sql_digest_is_independent_of_evidence_order(tmp_path: Path) -> None:
    inputs, path = fixture(tmp_path)
    first = execute(inputs, path, tmp_path / "first")
    # A second verified synthetic G3 artifact with reversed source ordering.
    inputs2 = inputs_v2(
        tmp_path / "second-input",
        [
            row(AlertId="09", Category="Phishing"),
            row(EntityType="Account"),
            row(),
            row(),
        ],
        [
            row(IncidentId="11", AlertId="15", IncidentGrade=""),
            row(IncidentId="10", Timestamp="2024-06-02T00:00:00Z"),
        ],
    )
    report2 = reconstruct(*inputs2, progress=quiet)
    doc = json.loads(path.read_text())
    doc["g3"] = {
        "reconstruction_sha256": report2["reconstruction_sha256"],
        "report_sha256": sha(inputs2[-1] / "report.json"),
        "database_sha256": sha(inputs2[-1] / "incidents.sqlite3"),
        "database_bytes": (inputs2[-1] / "incidents.sqlite3").stat().st_size,
    }
    path2 = tmp_path / "reordered-manifest.json"
    path2.write_text(json.dumps(doc))
    second = execute(inputs2, path2, tmp_path / "second")
    assert first["status"] == second["status"] == "PASSED"
    assert first["statistics"] == second["statistics"]
