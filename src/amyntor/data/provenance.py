"""G4 field decisions, separate from immutable G2/G3 contracts."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from amyntor.data.incidents import read_json
from amyntor.data.schema_contract import fingerprint, load_contract

COUNT = "snapshot_local_distinct_alert_count"
CANDIDATES = (
    "Category",
    "EntityType",
    "OSFamily",
    "OSVersion",
    "ResourceType",
    "AntispamDirection",
    COUNT,
)
MINIMUM = frozenset(("Category", "EntityType", COUNT))
Status = Literal["ACCEPTED", "EXCLUDED", "UNRESOLVED"]


class ProvenanceError(ValueError):
    """Unsupported or incomplete provenance/feature contract."""


@dataclass(frozen=True)
class Decision:
    name: str
    role: str
    status: Status
    source_references: tuple[str, ...]
    raw_representation: str
    null_rule: str
    transformation: str
    snapshot_availability: str
    point_in_time_availability: str
    leakage_risk: str
    rationale: str


@dataclass(frozen=True)
class Provenance:
    fields: dict[str, Decision]
    accepted: tuple[str, ...]
    source_columns: frozenset[str]
    g3: dict[str, str | int]
    sha256: str

    @property
    def categorical(self) -> tuple[str, ...]:
        return tuple(name for name in self.accepted if name != COUNT)

    @property
    def ready(self) -> bool:
        return MINIMUM.issubset(self.accepted) and all(
            self.fields[name].status != "UNRESOLVED" for name in CANDIDATES
        )


def load_provenance(path: Path, schema_path: Path) -> Provenance:
    doc = read_json(path)
    expected = {
        "version",
        "scope",
        "training_allowed",
        "statistical_leakage_clearance",
        "source_contract_sha256",
        "g3",
        "references",
        "accepted_fields",
        "fields",
    }
    schema = load_contract(schema_path)
    if (
        set(doc) != expected
        or doc["version"] != "guide-v1-provenance-1"
        or doc["scope"] != "retrospective-incident-snapshot-only"
        or doc["training_allowed"] is not False
        or doc["statistical_leakage_clearance"] != "PENDING_G5"
        or doc["source_contract_sha256"] != schema.sha256
    ):
        raise ProvenanceError("Unsupported provenance identity or scope")
    if not isinstance(doc["references"], dict) or not isinstance(doc["g3"], dict):
        raise ProvenanceError("Provenance references and G3 identity required")
    references = cast(dict[str, object], doc["references"])
    if not references or any(
        not isinstance(v, str) or not v for v in references.values()
    ):
        raise ProvenanceError("Nonempty evidence references required")
    pins = cast(dict[str, object], doc["g3"])
    if set(pins) != {
        "reconstruction_sha256",
        "report_sha256",
        "database_sha256",
        "database_bytes",
    }:
        raise ProvenanceError("G3 identity pins incomplete")
    for key in ("reconstruction_sha256", "report_sha256", "database_sha256"):
        if not isinstance(pins[key], str) or not re.fullmatch(
            "[0-9a-f]{64}", cast(str, pins[key])
        ):
            raise ProvenanceError("Invalid G3 digest")
    if type(pins["database_bytes"]) is not int or pins["database_bytes"] <= 0:
        raise ProvenanceError("Positive G3 database byte count required")
    if not isinstance(doc["fields"], list):
        raise ProvenanceError("Field decisions required")
    fields: dict[str, Decision] = {}
    roles = {name: column.role for name, column in schema.columns.items()}
    roles.update(
        {
            COUNT: "derived_candidate",
            "source_partition": "dataset_metadata",
            "source_usage": "dataset_metadata",
        }
    )
    for entry in cast(list[object], doc["fields"]):
        if not isinstance(entry, dict):
            raise ProvenanceError("Invalid field decision")
        item = cast(dict[str, object], entry)
        if set(item) != set(Decision.__dataclass_fields__):
            raise ProvenanceError("Incomplete field decision")
        if any(
            not isinstance(v, str) or not v
            for k, v in item.items()
            if k != "source_references"
        ):
            raise ProvenanceError("Nonempty field rationale/lineage required")
        name = cast(str, item["name"])
        status = item["status"]
        if name not in roles or name in fields or item["role"] != roles[name]:
            raise ProvenanceError("Unknown, repeated or incorrectly scoped field")
        if (
            status not in ("ACCEPTED", "EXCLUDED", "UNRESOLVED")
            or item["point_in_time_availability"] != "unproven"
        ):
            raise ProvenanceError("Unsupported decision or temporal claim")
        refs = item["source_references"]
        if not isinstance(refs, list):
            raise ProvenanceError("Field evidence references required")
        ref_values = cast(list[object], refs)
        if not ref_values or any(
            not isinstance(r, str) or r not in references for r in ref_values
        ):
            raise ProvenanceError("Unrecognized field evidence reference")
        if status == "ACCEPTED":
            if name not in CANDIDATES:
                raise ProvenanceError("Accepted input exceeds strict candidate ceiling")
            expected_transform = (
                "log1p-distinct-alerts-v1"
                if name == COUNT
                else "alert-set-presence-fraction-v1"
            )
            expected_null = (
                "nonempty-alert-membership"
                if name == COUNT
                else "empty-is-observed-absence-v1"
            )
            if (
                item["transformation"] != expected_transform
                or item["null_rule"] != expected_null
            ):
                raise ProvenanceError(
                    "Unsupported feature transformation or missingness rule"
                )
        fields[name] = Decision(
            name,
            cast(str, item["role"]),
            status,
            tuple(cast(list[str], refs)),
            *(
                cast(str, item[key])
                for key in (
                    "raw_representation",
                    "null_rule",
                    "transformation",
                    "snapshot_availability",
                    "point_in_time_availability",
                    "leakage_risk",
                    "rationale",
                )
            ),
        )
    if set(fields) != set(roles):
        raise ProvenanceError("Missing field decisions")
    accepted = tuple(name for name in CANDIDATES if fields[name].status == "ACCEPTED")
    if doc["accepted_fields"] != list(accepted):
        raise ProvenanceError("Accepted fields/order do not match decisions")
    return Provenance(
        fields,
        accepted,
        frozenset(schema.columns),
        cast(dict[str, str | int], pins),
        fingerprint(doc),
    )
