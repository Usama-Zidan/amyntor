"""The GUIDE v1 lexical contract; validating presence never approves a predictor."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from amyntor.data.acquisition import DATASET

Role = Literal[
    "required_identifier", "target", "candidate_input", "dataset_metadata", "excluded"
]
Representation = Literal[
    "unsigned_integer_string",
    "opaque_string",
    "categorical_text",
    "timestamp",
    "enum_string",
]
REQUIRED_IDS = frozenset({"OrgId", "IncidentId", "AlertId"})
CANDIDATES = frozenset(
    {
        "Category",
        "EntityType",
        "OSFamily",
        "OSVersion",
        "ResourceType",
        "AntispamDirection",
    }
)
LABELS = ("TruePositive", "BenignPositive", "FalsePositive")


class SchemaError(ValueError):
    """Invalid contract or a source/contract identity mismatch."""


@dataclass(frozen=True)
class ColumnContract:
    name: str
    role: Role
    representation: Representation
    nullable: bool
    model_status: str
    allowed_values: tuple[str, ...] = ()


@dataclass(frozen=True)
class FileContract:
    name: str
    header: tuple[str, ...]
    role: str


@dataclass(frozen=True)
class SchemaContract:
    version: str
    dataset_version: int
    source_manifest_sha256: str
    columns: dict[str, ColumnContract]
    files: tuple[FileContract, ...]
    null_tokens: tuple[str, ...]
    sentinel_tokens: tuple[str, ...]
    document: dict[str, object]
    sha256: str


def fingerprint(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, ensure_ascii=True, separators=(",", ":")
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _object(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise SchemaError("Contract object required")
    return cast(dict[str, object], value)


def _sequence(value: object) -> list[object]:
    if not isinstance(value, list):
        raise SchemaError("Contract array required")
    return cast(list[object], value)


def _string(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise SchemaError("Nonempty contract text required")
    return value


def _strings(value: object) -> tuple[str, ...]:
    return tuple(_string(item) for item in _sequence(value))


def load_contract(path: Path) -> SchemaContract:
    with path.open("rb") as stream:
        payload = stream.read(131073)
    if len(payload) > 131072:
        raise SchemaError("Contract exceeds 128 KiB")
    try:
        document = _object(cast(object, json.loads(payload)))
    except (UnicodeError, json.JSONDecodeError):
        raise SchemaError("Invalid contract JSON") from None
    if (
        document.get("dataset") != DATASET
        or type(document.get("dataset_version")) is not int
    ):
        raise SchemaError("Unsupported contract dataset identity")
    columns: dict[str, ColumnContract] = {}
    for item in _sequence(document.get("columns")):
        entry = _object(item)
        name = _string(entry.get("name"))
        role = entry.get("role")
        representation = entry.get("representation")
        nullable = entry.get("nullable")
        if (
            role
            not in {
                "required_identifier",
                "target",
                "candidate_input",
                "dataset_metadata",
                "excluded",
            }
            or representation
            not in {
                "unsigned_integer_string",
                "opaque_string",
                "categorical_text",
                "timestamp",
                "enum_string",
            }
            or type(nullable) is not bool
            or name in columns
        ):
            raise SchemaError("Invalid or duplicate column contract")
        model_status = _string(entry.get("model_status"))
        if model_status != ("UNRESOLVED" if role == "candidate_input" else "EXCLUDED"):
            raise SchemaError("G2 cannot approve any predictors")
        columns[name] = ColumnContract(
            name,
            cast(Role, role),
            cast(Representation, representation),
            nullable,
            model_status,
            _strings(entry.get("allowed_values", [])),
        )
    if {
        name for name, col in columns.items() if col.role == "required_identifier"
    } != set(REQUIRED_IDS):
        raise SchemaError("Required identifier contract changed")
    if {name for name, col in columns.items() if col.role == "candidate_input"} != set(
        CANDIDATES
    ):
        raise SchemaError("Candidate ceiling changed")
    target = columns.get("IncidentGrade")
    if target is None or target.role != "target" or target.allowed_values != LABELS:
        raise SchemaError("Disposition contract changed")
    files: list[FileContract] = []
    for item in _sequence(document.get("files")):
        entry = _object(item)
        name = _string(entry.get("name"))
        header = _strings(entry.get("header"))
        if Path(name).name != name or "/" in name or "\\" in name or not header:
            raise SchemaError("Invalid file contract")
        if len(set(header)) != len(header) or not set(header) <= columns.keys():
            raise SchemaError("Unreviewed or duplicate contract fields")
        if not (REQUIRED_IDS | {"IncidentGrade"} | CANDIDATES) <= set(header):
            raise SchemaError("Required/candidate column absent from contract")
        files.append(FileContract(name, header, _string(entry.get("role"))))
    if not files or len({file.name for file in files}) != len(files):
        raise SchemaError("Empty or duplicate source contracts")
    return SchemaContract(
        _string(document.get("contract_version")),
        cast(int, document["dataset_version"]),
        _string(document.get("source_manifest_sha256")),
        columns,
        tuple(files),
        _strings(document.get("null_like_tokens")),
        _strings(document.get("sentinel_probe_tokens")),
        document,
        fingerprint(document),
    )
