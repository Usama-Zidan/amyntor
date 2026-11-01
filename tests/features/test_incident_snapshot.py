from __future__ import annotations

import math
from dataclasses import replace
from pathlib import Path

import pytest

from amyntor.data.provenance import ProvenanceError, load_provenance
from amyntor.features.incident_snapshot import (
    Contribution,
    Evidence,
    ProjectionLimitError,
    ProjectionLimits,
    project_snapshot,
)

REPO = Path(__file__).resolve().parents[2]


def evidence(alert: str = "001", **values: object) -> Evidence:
    return Evidence(
        "01", "02", alert, {"Category": "Malware", "EntityType": "Device", **values}
    )


def test_exact_sets_fractions_order_and_repetition() -> None:
    contract = load_provenance(
        REPO / "configs/guide-v1.provenance.json", REPO / "configs/guide-v1.schema.json"
    )
    rows = [
        evidence(),
        evidence(),
        evidence(EntityType="Account"),
        evidence("1", Category="Phishing"),
    ]
    result = project_snapshot(rows, contract)
    assert result == project_snapshot(reversed(rows), contract)
    assert result.log1p_alert_count == math.log1p(2)
    assert result.categorical == {
        "Category": (
            Contribution("Malware", True, 0.5),
            Contribution("Phishing", True, 0.5),
        ),
        "EntityType": (
            Contribution("Account", True, 0.5),
            Contribution("Device", True, 1.0),
        ),
    }


def test_all_excluded_payload_fields_and_opaque_key_renaming_are_isolated() -> None:
    contract = load_provenance(
        REPO / "configs/guide-v1.provenance.json", REPO / "configs/guide-v1.schema.json"
    )
    rows = [evidence(), evidence("002")]
    expected = project_snapshot(rows, contract)
    for name in contract.source_columns - set(contract.categorical):
        changed = [replace(r, values={**r.values, name: object()}) for r in rows]
        assert project_snapshot(changed, contract) == expected
    renamed = [
        replace(r, org_id="0009", incident_id="0008", alert_id="prefix" + r.alert_id)
        for r in rows
    ]
    assert project_snapshot(renamed, contract) == expected
    assert "0009" not in str(expected)


def test_missing_literal_codes_and_numeric_looking_values_are_distinct() -> None:
    contract = load_provenance(
        REPO / "configs/guide-v1.provenance.json", REPO / "configs/guide-v1.schema.json"
    )
    rows = [
        evidence(str(n), EntityType=v)
        for n, v in enumerate(("", "NULL", "None", "0", "01", "1"))
    ]
    result = project_snapshot(rows, contract)
    assert {v.value for v in result.categorical["EntityType"]} == {
        None,
        "NULL",
        "None",
        "0",
        "01",
        "1",
    }
    assert all(v.fraction == 1 / 6 for v in result.categorical["EntityType"])


@pytest.mark.parametrize(
    "change", ["unexpected", "missing", "type", "outcome", "mixed", "empty"]
)
def test_invalid_inputs_fail_closed(change: str) -> None:
    contract = load_provenance(
        REPO / "configs/guide-v1.provenance.json", REPO / "configs/guide-v1.schema.json"
    )
    rows = [evidence()]
    if change == "unexpected":
        rows = [evidence(extra="not permitted")]
    elif change == "missing":
        rows = [replace(evidence(), values={"Category": "Malware"})]
    elif change == "type":
        rows = [evidence(Category=5)]
    elif change == "outcome":
        rows = [evidence(Category="TruePositive")]
    elif change == "mixed":
        rows.append(replace(evidence(), incident_id="different"))
    else:
        rows = []
    with pytest.raises(ProvenanceError):
        project_snapshot(rows, contract)


@pytest.mark.parametrize(
    "limits",
    [
        ProjectionLimits(max_rows=1),
        ProjectionLimits(max_alerts=1),
        ProjectionLimits(max_tokens=1),
        ProjectionLimits(max_characters=1),
        ProjectionLimits(max_field_chars=1),
    ],
)
def test_resource_limits_reject_instead_of_truncating(limits: ProjectionLimits) -> None:
    contract = load_provenance(
        REPO / "configs/guide-v1.provenance.json", REPO / "configs/guide-v1.schema.json"
    )
    with pytest.raises((ProjectionLimitError, ProvenanceError)):
        project_snapshot([evidence(), evidence("002")], contract, limits)
