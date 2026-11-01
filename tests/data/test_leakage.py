from __future__ import annotations

import itertools
import json
import os
import random
import socket
import sqlite3
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from amyntor.data.incidents import reconstruct, sha
from amyntor.data.leakage import audit, preflight
from amyntor.data.leakage_contract import LeakageError, load_audit_config
from amyntor.data.leakage_graph import (
    DDL,
    Budget,
    component_ids,
    component_statistics,
    flatten,
    hard_edge,
)
from amyntor.data.leakage_pairs import (
    apply_reviews,
    find_pairs,
    identifier_token,
    load_reviews,
)
from amyntor.data.leakage_review import finalize_reviews
from amyntor.data.provenance_validation import ValidationLimits, validate_g4
from amyntor.data.schema_contract import load_contract
from tests.data.test_incidents import REPO, Row, quiet, row
from tests.data.test_incidents_v2 import inputs_v2


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object, **kwargs: object) -> None:
        pytest.fail("G5 fixtures must not access the network")

    monkeypatch.setattr(socket.socket, "connect", fail)


def configuration() -> dict[str, object]:
    return json.loads(
        (REPO / "configs/guide-v1.leakage.json").read_text(encoding="utf-8")
    )


def fixture(
    tmp: Path, train: list[Row] | None = None, test: list[Row] | None = None
) -> tuple[list[Path], Path, Path, Path]:
    inputs = inputs_v2(
        tmp,
        train if train is not None else [row(), row(), row(DeviceId="0007")],
        test
        if test is not None
        else [row(IncidentId="10", IncidentGrade="FalsePositive")],
    )
    r3 = reconstruct(*inputs, progress=quiet)
    manifest = json.loads(
        (REPO / "configs/guide-v1.provenance.json").read_text(encoding="utf-8")
    )
    manifest["source_contract_sha256"] = load_contract(inputs[2]).sha256
    manifest["g3"] = {
        "reconstruction_sha256": r3["reconstruction_sha256"],
        "report_sha256": sha(inputs[-1] / "report.json"),
        "database_sha256": sha(inputs[-1] / "incidents.sqlite3"),
        "database_bytes": (inputs[-1] / "incidents.sqlite3").stat().st_size,
    }
    manifest_path = tmp / "provenance.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    r4 = validate_g4(
        inputs[-1],
        inputs[1],
        inputs[2],
        manifest_path,
        tmp / "g4-scratch",
        limits=ValidationLimits(minimum_free_bytes=1),
        progress=quiet,
    )
    assert r4["status"] == "PASSED"
    g4 = tmp / "g4.json"
    g4.write_text(json.dumps(r4, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    config = configuration()
    config["g4"] = {
        "report_bytes": g4.stat().st_size,
        "report_sha256": sha(g4),
        "validation_sha256": r4["validation_sha256"],
        "projection_sha256": cast(dict[str, object], r4["statistics"])[
            "unfitted_projection_sha256"
        ],
    }
    limits = cast(dict[str, object], config["limits"])
    limits["minimum_free_bytes"] = 1
    limits["retained_bytes"] = 16777216
    path = tmp / "leakage.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    return inputs, manifest_path, g4, path


def run_fixture(
    parts: tuple[list[Path], Path, Path, Path], tmp: Path, **kwargs: object
) -> dict[str, object]:
    inputs, manifest, g4, config = parts
    return audit(
        inputs[-1],
        g4,
        inputs[1],
        inputs[2],
        manifest,
        config,
        tmp / "scratch",
        tmp / "out",
        progress=quiet,
        benchmark_modulus=cast(int | None, kwargs.get("benchmark_modulus")),
        reviews=cast(Path | None, kwargs.get("reviews")),
    )


def test_complete_audit_is_blocked_by_unresolved_provenance_and_review(
    tmp_path: Path,
) -> None:
    parts = fixture(tmp_path / "input")
    sources = [
        parts[0][-1] / "incidents.sqlite3",
        parts[0][-1] / "report.json",
        parts[2],
    ]
    before = {p: sha(p) for p in sources}
    report = run_fixture(parts, tmp_path / "run")
    assert report["status"] == "BLOCKED", report
    assert report["completed_work"] is True, report
    assert report["source_verified"] is True
    assert report["training_allowed"] is False
    checks = cast(dict[str, bool], report["checks"])
    assert checks["row_accounting"] and checks["retained_memberships_reconciled"]
    assert checks["hard_edges_internal"] and checks["component_accounting"]
    assert not checks["identifier_provenance_resolved"]
    stats = cast(dict[str, object], report["statistics"])
    assert stats["evidence_rows_decoded"] == 4
    assert stats["retained_incidents"] == 2
    assert all(sha(p) == digest for p, digest in before.items())
    public = json.dumps(report)
    assert '"0007"' not in public and '"Malware"' not in public and '"01"' not in public
    assert (tmp_path / "run/out/lineage.sqlite3").is_file()


def test_quarantine_bridge_and_cross_source_reuse(tmp_path: Path) -> None:
    parts = fixture(
        tmp_path / "input",
        [
            row(IncidentId="00", AlertId="111"),
            row(IncidentId="01", AlertId="111", IncidentGrade=""),
            row(IncidentId="01", AlertId="112", IncidentGrade=""),
        ],
        [row(IncidentId="02", AlertId="112", IncidentGrade="BenignPositive")],
    )
    report = run_fixture(parts, tmp_path / "run")
    assert report["completed_work"] is True, report
    stats = cast(dict[str, object], report["statistics"])
    assert (
        cast(dict[str, object], stats["components_with_quarantine_bridges"])[
            "retained_components"
        ]
        == 1
    )
    assert (
        cast(dict[str, object], stats["components_without_quarantine_bridges"])[
            "retained_components"
        ]
        == 2
    )
    assert stats["quarantine_bridged_retained_components"] == 1
    assert stats["retained_incidents"] == 2 and stats["full_context_incidents"] == 3


@pytest.mark.parametrize(
    "change",
    ["g4_bytes", "g4_identity", "g4_code", "g3_bytes", "g3_same_size", "g4_symlink"],
)
def test_invalid_artifacts_never_reach_payload_scan(
    change: str, tmp_path: Path
) -> None:
    parts = fixture(tmp_path / "input")
    inputs, manifest, g4, config = parts
    if change in {"g4_identity", "g4_code"}:
        report = json.loads(g4.read_text())
        if change == "g4_code":
            report["code_sha256"]["provenance.py"] = "0" * 64
        else:
            report["validation_sha256"] = "0" * 64
        g4.write_text(json.dumps(report))
        cfg = json.loads(config.read_text())
        cfg["g4"]["report_bytes"], cfg["g4"]["report_sha256"] = (
            g4.stat().st_size,
            sha(g4),
        )
        config.write_text(json.dumps(cfg))
    elif change == "g4_bytes":
        g4.write_bytes(g4.read_bytes() + b" ")
    elif change == "g4_symlink":
        target = g4.with_name("target.json")
        g4.rename(target)
        try:
            g4.symlink_to(target)
        except OSError:
            pytest.skip("Creating symlinks unavailable for this Windows account")
    else:
        database = inputs[-1] / "incidents.sqlite3"
        if change == "g3_same_size":
            with database.open("r+b") as stream:
                stream.seek(100)
                stream.write(b"altered")
        else:
            with database.open("ab") as stream:
                stream.write(b"altered")
    if change == "g3_same_size":
        report = run_fixture(parts, tmp_path / "run")
        assert report["status"] == "BLOCKED" and report["source_verified"] is False
    else:
        with pytest.raises(ValueError):
            preflight(
                inputs[-1],
                g4,
                inputs[1],
                inputs[2],
                manifest,
                config,
                tmp_path / "s",
                tmp_path / "o",
            )
    assert not (tmp_path / "run/out/lineage.sqlite3").exists()


def graph_db(path: Path, size: int) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.executescript(DDL)
    for number in range(1, size + 1):
        connection.execute(
            "INSERT INTO nodes VALUES (?,?,?,?,?,?,?,?,?)",
            (
                number,
                "0001",
                f"{number:04}",
                1,
                "TruePositive",
                1,
                number,
                number,
                number,
            ),
        )
    return connection


def test_components_transitive_cycles_and_order_invariance(tmp_path: Path) -> None:
    config = load_audit_config(REPO / "configs/guide-v1.leakage.json")
    fingerprints: list[list[tuple[str]]] = []
    for name, edges in (
        ("forward", [(1, 2), (2, 3), (3, 1), (4, 5)]),
        ("reverse", [(5, 4), (1, 3), (3, 2), (2, 1)]),
    ):
        with graph_db(tmp_path / (name + ".sqlite3"), 6) as connection:
            for a, b in edges:
                hard_edge(connection, a, b, "test_verified_hard")
            budget = Budget(tmp_path, config.limits)
            flatten(connection, budget)
            component_ids(connection, budget)
            result = component_statistics(connection, "p_all")
            assert result["retained_components"] == 3
            assert cast(dict[str, object], result["size"])["max"] == 3
            fingerprints.append(
                connection.execute(
                    "SELECT digest FROM component_ids ORDER BY digest"
                ).fetchall()
            )
    assert fingerprints[0] == fingerprints[1]


@pytest.mark.parametrize("seed", [0, 1, 19])
def test_exact_jaccard_against_exhaustive_oracle(seed: int, tmp_path: Path) -> None:
    config = load_audit_config(REPO / "configs/guide-v1.leakage.json")
    rng = random.Random(seed)
    sets: list[set[int]] = [
        set(range(20)),
        set(range(18)),
        set(range(19)),
        set(range(17)),
        set(),
        {80},
        {81, 82},
    ]
    sets += [set(rng.sample(range(25), rng.randrange(2, 25))) for _ in range(15)]
    with graph_db(tmp_path / "pairs.sqlite3", len(sets)) as connection:
        for node, values in enumerate(sets, 1):
            connection.executemany(
                "INSERT INTO tokens VALUES (?,?,?,1,0)",
                ((node, "AlertId", str(v).encode()) for v in values),
            )
        find_pairs(connection, config, Budget(tmp_path, config.limits))
        actual = set(
            connection.execute("SELECT a,b FROM pairs WHERE flagged=1").fetchall()
        )
        expected = {
            (a + 1, b + 1)
            for a, b in itertools.combinations(range(len(sets)), 2)
            if len(sets[a] & sets[b]) >= 2
            and 10 * len(sets[a] & sets[b]) >= 9 * len(sets[a] | sets[b])
        }
        assert actual == expected


def test_sentinel_ambiguity_scope_and_opaque_zero(tmp_path: Path) -> None:
    config = load_audit_config(REPO / "configs/guide-v1.leakage.json")
    alert, entity = config.identifiers[:2]
    assert identifier_token(alert, "0001", "0") is not None
    assert identifier_token(alert, "0001", "0007") != identifier_token(
        alert, "0002", "0007"
    )
    assert identifier_token(alert, "0001", "0007") != identifier_token(
        alert, "0001", "7"
    )
    ambiguous = identifier_token(entity, "0001", "0")
    assert ambiguous is not None and ambiguous[1:] == (False, True)
    assert identifier_token(entity, "0001", "") is None
    doc = configuration()
    cast(list[dict[str, object]], doc["identifiers"])[1]["copy_eligible"] = True
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(doc))
    with pytest.raises(LeakageError):
        load_audit_config(path)


def test_source_only_preflight_command_and_required_explicit_mode(
    tmp_path: Path,
) -> None:
    inputs, manifest, g4, config = fixture(tmp_path / "input")
    command = [sys.executable, "-S", "-m", "amyntor.data.audit_leakage"]
    for flag, path in (
        ("g3-output", inputs[-1]),
        ("g4-report", g4),
        ("lock", inputs[1]),
        ("schema", inputs[2]),
        ("manifest", manifest),
        ("config", config),
        ("scratch", tmp_path / "s"),
        ("output", tmp_path / "o"),
    ):
        command += ["--" + flag, str(path)]
    env = {**os.environ, "PYTHONPATH": str(REPO / "src")}
    for mode, expected in (([], 2), (["--preflight-only"], 0)):
        result = subprocess.run(
            [*command, *mode],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == expected, result.stdout + result.stderr
    assert not (tmp_path / "s").exists() and not (tmp_path / "o").exists()
    result = subprocess.run(
        [*command, "--full"],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert json.loads((tmp_path / "o/report.json").read_text())["status"] == "BLOCKED"


def test_resource_and_benchmark_failures_cannot_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parts = fixture(tmp_path / "input")
    cfg = json.loads(parts[-1].read_text())
    cfg["limits"]["scratch_bytes"] = 1
    parts[-1].write_text(json.dumps(cfg))
    report = run_fixture(parts, tmp_path / "disk")
    assert (
        report["status"] == "INCOMPLETE" and report["failure"] == "resource_preflight"
    )
    cfg["limits"]["scratch_bytes"] = 137438953472
    parts[-1].write_text(json.dumps(cfg))
    monkeypatch.setattr("amyntor.data.leakage_graph.time.monotonic", lambda: 0.0)
    from amyntor.data.leakage_contract import AuditLimit

    config = load_audit_config(parts[-1])
    budget = Budget(tmp_path, config.limits)
    budget.started = -30000.0
    with pytest.raises(AuditLimit, match="time_limit"):
        budget.check()


def test_benchmark_remains_partial_even_when_selected_scope_completes(
    tmp_path: Path,
) -> None:
    parts = fixture(
        tmp_path / "input",
        [row(IncidentId=str(i), AlertId=str(i)) for i in range(15)],
        [row(IncidentId="9999", AlertId="9999")],
    )
    report = run_fixture(parts, tmp_path / "run", benchmark_modulus=2)
    assert report["status"] == "PARTIAL", report
    assert report["training_allowed"] is False
    assert report["completed_work"] is True


def test_unresolved_entity_equality_is_only_a_sensitivity_bound(tmp_path: Path) -> None:
    parts = fixture(
        tmp_path / "input",
        [row(OrgId="001", IncidentId="0002", DeviceId="0")],
        [row(OrgId="002", IncidentId="0002", DeviceId="0")],
    )
    report = run_fixture(parts, tmp_path / "run")
    assert report["completed_work"] is True, report
    stats = cast(dict[str, object], report["statistics"])
    assert (
        cast(dict[str, object], stats["components_with_quarantine_bridges"])[
            "retained_components"
        ]
        == 2
    )
    assert (
        cast(
            dict[str, object], stats["code_equality_sensitivity_not_confirmed_identity"]
        )["retained_components"]
        == 1
    )
    assert cast(dict[str, object], stats["copy_candidates"])["flagged_pairs"] == 0
    with sqlite3.connect(tmp_path / "run/out/lineage.sqlite3") as connection:
        assert {
            r[0]
            for r in connection.execute(
                "SELECT DISTINCT stratum FROM contingencies WHERE scope='source_membership'"
            )
        } == {"GUIDE_Train.csv", "GUIDE_Test.csv"}


@pytest.mark.parametrize(
    "which", ["candidate", "disk_floor", "retained", "oversized_payload"]
)
def test_resource_failures_are_explicit(
    which: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from amyntor.data.leakage_contract import AuditLimit

    if which == "candidate":
        cfg = load_audit_config(REPO / "configs/guide-v1.leakage.json")
        with graph_db(tmp_path / "pairs.sqlite3", 3) as connection:
            connection.executemany(
                "INSERT INTO tokens VALUES (?,?,?,1,0)",
                [
                    (n, "AlertId", str(t).encode())
                    for n in range(1, 4)
                    for t in range(2)
                ],
            )
            with pytest.raises(AuditLimit, match="candidate_attempt_limit"):
                find_pairs(
                    connection,
                    cfg,
                    Budget(tmp_path, replace(cfg.limits, candidate_attempts=1)),
                )
        return
    parts = fixture(tmp_path / "input")
    cfg = json.loads(parts[-1].read_text())
    if which == "disk_floor":
        cfg["limits"]["minimum_free_bytes"] = 2**63
    elif which == "retained":
        cfg["limits"]["retained_bytes"] = 1
    else:
        cfg["limits"]["payload_chars"] = 1
    parts[-1].write_text(json.dumps(cfg))
    report = run_fixture(parts, tmp_path / "run")
    assert report["status"] == "INCOMPLETE", report
    assert report["failure"] is not None
    assert report.get("lineage_accepted", False) is False


@pytest.mark.parametrize(
    "change",
    [
        "raised_limit",
        "inferred_scope",
        "outcome_registry",
        "ambiguous_alert",
        "changed_threshold",
    ],
)
def test_configuration_fails_closed(change: str, tmp_path: Path) -> None:
    doc = configuration()
    registry = cast(list[dict[str, object]], doc["identifiers"])
    if change == "raised_limit":
        cast(dict[str, object], doc["limits"])["max_seconds"] = 28801
    elif change == "inferred_scope":
        registry[1]["copy_eligible"] = True
    elif change == "outcome_registry":
        registry[1]["field"] = "LastVerdict"
    elif change == "ambiguous_alert":
        registry[0]["verified_sentinels"] = ["0"]
    else:
        cast(dict[str, object], doc["rules"])["jaccard_numerator"] = 8
    path = tmp_path / "config.json"
    path.write_text(json.dumps(doc))
    with pytest.raises(LeakageError):
        load_audit_config(path)


def test_required_pair_review_not_replaced_by_sampling(tmp_path: Path) -> None:
    config = load_audit_config(REPO / "configs/guide-v1.leakage.json")
    with graph_db(tmp_path / "review.sqlite3", 3) as connection:
        connection.executemany(
            "INSERT INTO tokens VALUES (?,?,?,1,0)",
            [(n, "AlertId", str(t).encode()) for n in range(1, 4) for t in range(2)],
        )
        budget = Budget(tmp_path, config.limits)
        find_pairs(connection, config, budget)
        identity = "a" * 64
        pair = connection.execute(
            "SELECT pair_id FROM pairs ORDER BY pair_id LIMIT 1"
        ).fetchone()[0]
        path = tmp_path / "reviews.jsonl"
        path.write_text(
            json.dumps(
                {"gate": "G5_REVIEW", "audit_identity": identity, "label_blind": True}
            )
            + "\n"
            + json.dumps(
                {
                    "id": pair,
                    "kind": "pair",
                    "decision": "CONSERVATIVE_DEPENDENCY",
                    "evidence": "synthetic structure correspondence",
                    "rationale": "No labels inspected",
                }
            )
            + "\n"
        )
        load_reviews(connection, path, identity, config, budget)
        counts = apply_reviews(connection, budget)
        assert counts["unresolved_pairs"] == 2
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM edges WHERE kind='reviewed_conservative'"
            ).fetchone()[0]
            == 1
        )
        with pytest.raises(LeakageError):
            load_reviews(connection, path, "b" * 64, config, budget)


@pytest.mark.parametrize("resolved_registry", [False, True])
def test_review_only_reuses_complete_artifacts_without_payload_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, resolved_registry: bool
) -> None:
    parts = fixture(tmp_path / "input")
    if resolved_registry:
        doc = json.loads(parts[-1].read_text())
        for rule in doc["identifiers"][1:]:
            rule["status"], rule["scope"] = "VERIFIED", "organization"
            rule["evidence"] = (
                "Synthetic fixture-only identity semantics; not GUIDE provenance"
            )
        parts[-1].write_text(json.dumps(doc))
    first = run_fixture(parts, tmp_path / "first")
    assert first["completed_work"] is True, first
    prior = tmp_path / "first/out/report.json"
    prior.write_text(json.dumps(first))
    reviews = tmp_path / "reviews.jsonl"
    records = [
        {
            "gate": "G5_REVIEW",
            "audit_identity": first["audit_identity"],
            "label_blind": True,
        }
    ]
    with sqlite3.connect(prior.parent / "lineage.sqlite3") as connection:
        for (identity,) in connection.execute("SELECT id FROM findings ORDER BY id"):
            records.append(
                {
                    "id": identity,
                    "kind": "finding",
                    "decision": "RETROSPECTIVE_LIMITATION",
                    "evidence": "Synthetic retrospective fixture only",
                    "rationale": "No prospective or training claim",
                }
            )
    reviews.write_text("\n".join(json.dumps(r) for r in records) + "\n")

    def fail(*args: object, **kwargs: object) -> None:
        pytest.fail("Review-only must not decode evidence or rerun candidate search")

    monkeypatch.setattr("amyntor.data.leakage.ingest", fail)
    monkeypatch.setattr("amyntor.data.leakage.find_pairs", fail)
    inputs, manifest, g4, config = parts
    result = finalize_reviews(
        inputs[-1],
        g4,
        inputs[1],
        inputs[2],
        manifest,
        config,
        tmp_path / "review-scratch",
        tmp_path / "review-out",
        prior,
        sha(prior),
        reviews,
    )
    assert result["payload_pass_reused"] is True
    assert result["status"] == ("PASSED" if resolved_registry else "BLOCKED")
    assert result["training_allowed"] is False
    assert result["lineage_accepted"] is resolved_registry
    assert cast(dict[str, bool], result["checks"])["required_review_resolved"] is True
    with pytest.raises(LeakageError):
        finalize_reviews(
            inputs[-1],
            g4,
            inputs[1],
            inputs[2],
            manifest,
            config,
            tmp_path / "bad-s",
            tmp_path / "bad-o",
            prior,
            "0" * 64,
            reviews,
        )


def test_entity_only_matching_catches_renamed_alert_candidates_without_auto_edges(
    tmp_path: Path,
) -> None:
    config = load_audit_config(REPO / "configs/guide-v1.leakage.json")
    answers: list[list[tuple[str, int, int, str]]] = []
    for label in ("TruePositive", "FalsePositive"):
        with graph_db(tmp_path / (label + ".sqlite3"), 2) as connection:
            connection.execute("UPDATE nodes SET grade=?", (label,))
            for node in (1, 2):
                connection.execute(
                    "INSERT INTO tokens VALUES (?,?,?,1,0)",
                    (node, "AlertId", f"unique-{node}".encode()),
                )
                connection.executemany(
                    "INSERT INTO tokens VALUES (?,?,?,1,0)",
                    [(node, "DeviceId", value) for value in (b"device-A", b"device-B")],
                )
                connection.execute(
                    "INSERT INTO outcomes VALUES (?,?,?,0)",
                    (node, "LastVerdict", label.encode()),
                )
            find_pairs(connection, config, Budget(tmp_path, config.limits))
            answers.append(
                connection.execute(
                    "SELECT pair_id,shared,denominator,universe FROM pairs WHERE flagged=1"
                ).fetchall()
            )
            assert answers[-1][0][3] == "verified_entity_only"
            assert connection.execute("SELECT COUNT(*) FROM edges").fetchone()[0] == 0
    assert answers[0] == answers[1]


def test_review_duplicates_and_unknown_decisions_fail_closed(tmp_path: Path) -> None:
    config = load_audit_config(REPO / "configs/guide-v1.leakage.json")
    with graph_db(tmp_path / "review.sqlite3", 2) as connection:
        connection.executemany(
            "INSERT INTO tokens VALUES (?,?,?,1,0)",
            [(node, "AlertId", value) for node in (1, 2) for value in (b"a", b"b")],
        )
        budget = Budget(tmp_path, config.limits)
        find_pairs(connection, config, budget)
        pair = connection.execute("SELECT pair_id FROM pairs").fetchone()[0]
        header = {"gate": "G5_REVIEW", "audit_identity": "a" * 64, "label_blind": True}
        decision = {
            "id": pair,
            "kind": "pair",
            "decision": "DISTINCT",
            "evidence": "synthetic evidence",
            "rationale": "distinct observations",
        }
        path = tmp_path / "review.jsonl"
        path.write_text(
            "\n".join(json.dumps(v) for v in (header, decision, decision)) + "\n"
        )
        with pytest.raises(LeakageError, match="Duplicate"):
            load_reviews(connection, path, "a" * 64, config, budget)


def test_shuffled_fixture_preserves_components_and_copy_candidates(
    tmp_path: Path,
) -> None:
    train = [
        row(IncidentId="0001", AlertId="10"),
        row(IncidentId="0001", AlertId="11"),
        row(IncidentId="0001", AlertId="10"),
    ]
    test = [
        row(IncidentId="0002", AlertId="10", IncidentGrade="FalsePositive"),
        row(IncidentId="0002", AlertId="11", IncidentGrade="FalsePositive"),
    ]
    signatures: list[object] = []
    for name, rows1, rows2 in (
        ("forward", train, test),
        ("reverse", list(reversed(train)), list(reversed(test))),
    ):
        parts = fixture(tmp_path / name / "input", rows1, rows2)
        report = run_fixture(parts, tmp_path / name / "run")
        assert report["completed_work"] is True, report
        with sqlite3.connect(tmp_path / name / "run/out/lineage.sqlite3") as connection:
            signatures.append(
                (
                    connection.execute(
                        "SELECT digest FROM component_ids ORDER BY digest"
                    ).fetchall(),
                    connection.execute(
                        "SELECT pair_id,shared,denominator,flagged FROM pairs ORDER BY pair_id"
                    ).fetchall(),
                )
            )
    assert signatures[0] == signatures[1]


def test_symlink_rejection_without_platform_symlink_privileges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs, manifest, g4, config = fixture(tmp_path / "input")
    actual = Path.is_symlink

    def simulated(path: Path) -> bool:
        return path == g4 or actual(path)

    monkeypatch.setattr(Path, "is_symlink", simulated)
    with pytest.raises(LeakageError, match="non-symlink"):
        preflight(
            inputs[-1],
            g4,
            inputs[1],
            inputs[2],
            manifest,
            config,
            tmp_path / "s",
            tmp_path / "o",
        )


def test_exact_hard_path_accounts_for_pair_without_claiming_copy(
    tmp_path: Path,
) -> None:
    config = load_audit_config(REPO / "configs/guide-v1.leakage.json")
    with graph_db(tmp_path / "graph.sqlite3", 3) as connection:
        connection.executemany(
            "INSERT INTO tokens VALUES (?,?,?,1,0)",
            [(n, "AlertId", t) for n in (1, 2, 3) for t in (b"a", b"b")],
        )
        hard_edge(connection, 1, 2, "scoped_alert")
        hard_edge(connection, 2, 3, "scoped_alert")
        budget = Budget(tmp_path, config.limits)
        find_pairs(connection, config, budget)
        result = apply_reviews(connection, budget)
        assert result["unresolved_pairs"] == 0 and result["reviewed_pairs"] == 0
        assert result["pairs_resolved_by_verified_hard_path"] == 3
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM edges WHERE kind='reviewed_copy'"
            ).fetchone()[0]
            == 0
        )


def test_retention_hashing_cannot_outlive_the_deadline_and_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from amyntor.data.leakage import retain
    from amyntor.data.leakage_contract import AuditLimit

    parts = fixture(tmp_path / "input")
    report = run_fixture(parts, tmp_path / "run")
    assert report["completed_work"] is True, report
    config = load_audit_config(parts[-1])
    budget = Budget(tmp_path, config.limits)

    def slow_hash(path: Path) -> str:
        budget.started -= 30000
        return sha(path)

    monkeypatch.setattr("amyntor.data.leakage.sha", slow_hash)
    output = tmp_path / "retained-again"
    output.mkdir()
    with sqlite3.connect(tmp_path / "run/scratch/audit.sqlite3") as connection:
        with pytest.raises(AuditLimit, match="time_limit"):
            retain(
                connection,
                output,
                cast(str, report["audit_identity"]),
                budget,
                config.document,
            )
