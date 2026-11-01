"""Unfitted G4 projection. IDs organize membership but never enter feature values."""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from amyntor.data.provenance import Provenance, ProvenanceError


class ProjectionLimitError(ValueError):
    """A resource bound was exceeded; never truncate a snapshot."""


@dataclass(frozen=True)
class Evidence:
    org_id: str
    incident_id: str
    alert_id: str
    values: Mapping[str, object]


@dataclass(frozen=True)
class ProjectionLimits:
    max_rows: int = 100000
    max_alerts: int = 10000
    max_tokens: int = 200000
    max_characters: int = 8388608
    max_field_chars: int = 65536


@dataclass(frozen=True)
class Contribution:
    value: str | None  # None means observed empty cell, not an inferred sentinel.
    presence: bool
    fraction: float


@dataclass(frozen=True)
class SnapshotProjection:
    categorical: dict[str, tuple[Contribution, ...]]
    log1p_alert_count: float


def accepted_values(
    values: Mapping[str, object], contract: Provenance, maximum: int
) -> tuple[tuple[str, str], ...]:
    """Read only whitelisted values; do not inspect excluded payload contents."""
    if set(values) - contract.source_columns:
        raise ProvenanceError("Unexpected source field")
    result: list[tuple[str, str]] = []
    for name in contract.categorical:
        if name not in values:
            raise ProvenanceError("Missing or incompatible accepted field")
        value = values[name]
        if not isinstance(value, str):
            raise ProvenanceError("Missing or incompatible accepted field")
        if len(value) > maximum:
            raise ProjectionLimitError("Accepted field exceeds resource bound")
        if value in {
            "TruePositive",
            "BenignPositive",
            "FalsePositive",
            "true_positive",
            "benign_positive",
            "false_positive",
        }:
            raise ProvenanceError(
                "Disposition token in context field requires provenance review"
            )
        result.append((name, value))
    return tuple(result)


def contribution(value: str, count: int, alerts: int) -> Contribution:
    if not 0 < count <= alerts:
        raise ProvenanceError("Invalid distinct-alert contribution")
    return Contribution(value if value else None, True, count / alerts)


DEFAULT_LIMITS = ProjectionLimits()


def opaque_key(value: object, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ProvenanceError("Opaque nonempty string identities required")
    return value


def project_snapshot(
    rows: Iterable[Evidence],
    contract: Provenance,
    limits: ProjectionLimits = DEFAULT_LIMITS,
) -> SnapshotProjection:
    if not contract.ready:
        raise ProvenanceError(
            "Minimum accepted contract or candidate decisions incomplete"
        )
    if (
        min(
            limits.max_rows,
            limits.max_alerts,
            limits.max_tokens,
            limits.max_characters,
            limits.max_field_chars,
        )
        <= 0
    ):
        raise ProjectionLimitError("Positive resource bounds required")
    membership: tuple[str, str] | None = None
    alerts: dict[str, set[tuple[str, str]]] = {}
    tokens = characters = 0
    for number, row in enumerate(rows, 1):
        if number > limits.max_rows:
            raise ProjectionLimitError("Snapshot row limit")
        keys = (
            opaque_key(row.org_id, limits.max_field_chars),
            opaque_key(row.incident_id, limits.max_field_chars),
            opaque_key(row.alert_id, limits.max_field_chars),
        )
        if membership is None:
            membership = keys[:2]
        if membership != keys[:2]:
            raise ProvenanceError("Projection accepts exactly one incident")
        if row.alert_id not in alerts:
            if len(alerts) >= limits.max_alerts:
                raise ProjectionLimitError("Snapshot alert limit")
            characters += len(row.alert_id)
            alerts[row.alert_id] = set()
        target = alerts[row.alert_id]
        for pair in accepted_values(row.values, contract, limits.max_field_chars):
            if pair not in target:
                tokens += 1
                characters += len(pair[0]) + len(pair[1])
                if tokens > limits.max_tokens or characters > limits.max_characters:
                    raise ProjectionLimitError("Snapshot value-state limit")
                target.add(pair)
    if not alerts:
        raise ProvenanceError("Empty snapshot")
    counts: Counter[tuple[str, str]] = Counter()
    for values in alerts.values():
        counts.update(values)
    projected: dict[str, tuple[Contribution, ...]] = {}
    for name in contract.categorical:
        projected[name] = tuple(
            contribution(value, counts[name, value], len(alerts))
            for value in sorted(value for field, value in counts if field == name)
        )
    return SnapshotProjection(projected, math.log1p(len(alerts)))
