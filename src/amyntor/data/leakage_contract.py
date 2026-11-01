"""G5 configuration and strict adapters around unchanged G3/G4 integrity code."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from amyntor.data.incidents import read_json, sha, verify_output
from amyntor.data.provenance import Provenance, load_provenance
from amyntor.data.schema_contract import fingerprint, load_contract

ENTITY_FIELDS = (
    "DeviceId",
    "Sha256",
    "IpAddress",
    "Url",
    "AccountSid",
    "AccountUpn",
    "AccountObjectId",
    "AccountName",
    "DeviceName",
    "NetworkMessageId",
    "EmailClusterId",
    "RegistryKey",
    "RegistryValueName",
    "RegistryValueData",
    "ApplicationId",
    "ApplicationName",
    "OAuthApplicationId",
    "FileName",
    "FolderPath",
    "ResourceIdName",
)


class LeakageError(ValueError):
    """An untrusted artifact or unsupported G5 contract must fail closed."""


class AuditLimit(RuntimeError):
    """Partial computation never establishes G5 clearance."""


@dataclass(frozen=True)
class Identifier:
    field: str
    representation: str
    status: str
    scope: str
    verified_sentinels: tuple[str, ...]
    ambiguous_values: tuple[str, ...]
    evidence: str
    copy_eligible: bool


@dataclass(frozen=True)
class Limits:
    scratch_bytes: int
    max_seconds: int
    candidate_attempts: int
    minimum_free_bytes: int
    retained_bytes: int
    cache_mib: int
    batch_rows: int
    batch_bytes: int
    field_chars: int
    payload_chars: int
    review_line_bytes: int
    benchmark_incidents: int
    benchmark_evidence_rows: int


@dataclass(frozen=True)
class AuditConfig:
    document: dict[str, object]
    identifiers: tuple[Identifier, ...]
    limits: Limits
    sha256: str

    @property
    def rules(self) -> dict[str, object]:
        return cast(dict[str, object], self.document["rules"])


def load_audit_config(path: Path) -> AuditConfig:
    doc = read_json(path)
    if set(doc) != {
        "version",
        "training_allowed",
        "g4",
        "limits",
        "rules",
        "identifiers",
    }:
        raise LeakageError("Unexpected G5 configuration keys")
    if doc["version"] != "guide-v1-leakage-1" or doc["training_allowed"] is not False:
        raise LeakageError("Unsupported G5 version or training claim")
    if any(
        not isinstance(doc[key], dict) for key in ("g4", "limits", "rules")
    ) or not isinstance(doc["identifiers"], list):
        raise LeakageError(
            "G5 pins/limits/rules must be objects and identifiers a list"
        )
    pins = cast(dict[str, object], doc["g4"])
    if set(pins) != {
        "report_bytes",
        "report_sha256",
        "validation_sha256",
        "projection_sha256",
    }:
        raise LeakageError("Incomplete G4 pins")
    if type(pins["report_bytes"]) is not int or pins["report_bytes"] <= 0:
        raise LeakageError("Invalid G4 size pin")
    if any(
        not isinstance(v, str) or not re.fullmatch("[0-9a-f]{64}", v)
        for k, v in pins.items()
        if k != "report_bytes"
    ):
        raise LeakageError("Invalid G4 digest pin")
    raw_limits = cast(dict[str, object], doc["limits"])
    if set(raw_limits) != set(Limits.__dataclass_fields__) or any(
        type(v) is not int or v <= 0 for v in raw_limits.values()
    ):
        raise LeakageError("Positive explicit G5 bounds required")
    limits = Limits(**cast(dict[str, int], raw_limits))
    if (
        limits.scratch_bytes > 137438953472
        or limits.max_seconds > 28800
        or limits.candidate_attempts > 20000000
        or limits.cache_mib > 64
        or limits.batch_rows > 2048
        or limits.batch_bytes > 4194304
        or limits.field_chars > 65536
        or limits.payload_chars > 8388608
        or limits.retained_bytes > 2147483648
        or limits.review_line_bytes > 65536
        or limits.benchmark_incidents > 20000
        or limits.benchmark_evidence_rows > 500000
    ):
        raise LeakageError(
            "G5 provisional upper bounds require explicit protocol revision"
        )
    rules = cast(dict[str, object], doc["rules"])
    expected_rules = {
        "jaccard_numerator",
        "jaccard_denominator",
        "minimum_shared_tokens",
        "discriminative_max_incidents",
        "review_sample_size",
        "missingness_gap",
        "minimum_comparison_support",
        "quarantine_bridges",
        "benchmark_salt",
        "token_universes",
        "existing_hard_path_resolves_independence",
    }
    if (
        set(rules) != expected_rules
        or rules["jaccard_numerator"] != 9
        or rules["jaccard_denominator"] != 10
        or rules["minimum_shared_tokens"] != 2
        or rules["quarantine_bridges"] is not True
        or rules["missingness_gap"] != 0.1
        or rules["minimum_comparison_support"] != 100
        or rules["review_sample_size"] != 100
        or rules["benchmark_salt"] != "guide-g5-benchmark-v1|17|"
        or rules["token_universes"] != ["all_verified_identity", "verified_entity_only"]
        or rules["existing_hard_path_resolves_independence"] is not True
    ):
        raise LeakageError("Unsupported G5 dependency/review rules")
    if (
        type(rules["discriminative_max_incidents"]) is not int
        or not 2 <= rules["discriminative_max_incidents"] <= 1000
    ):
        raise LeakageError(
            "Discriminative incidence bound must be explicit and <= 1000"
        )
    identifiers: list[Identifier] = []
    for entry in cast(list[object], doc["identifiers"]):
        if not isinstance(entry, dict):
            raise LeakageError("Every identifier must have an explicit typed decision")
        raw = cast(dict[str, object], entry)
        if set(raw) != set(Identifier.__dataclass_fields__):
            raise LeakageError("Incomplete identifier provenance")
        for key in ("field", "representation", "status", "scope", "evidence"):
            if not isinstance(raw[key], str) or not raw[key]:
                raise LeakageError("Identifier evidence and lexical scope required")
        for key in ("verified_sentinels", "ambiguous_values"):
            if not isinstance(raw[key], list) or any(
                not isinstance(v, str) for v in cast(list[object], raw[key])
            ):
                raise LeakageError("Sentinel spellings must remain explicit strings")
        if (
            raw["status"] not in ("VERIFIED", "UNRESOLVED")
            or raw["scope"] not in ("organization", "global", "unresolved")
            or type(raw["copy_eligible"]) is not bool
        ):
            raise LeakageError("Unsupported identifier decision")
        if raw["representation"] != (
            "unsigned_integer_string" if raw["field"] == "AlertId" else "opaque_string"
        ):
            raise LeakageError(
                "Identifier representation must match the unchanged G2 lexical contract"
            )
        if raw["copy_eligible"] and (
            raw["status"] != "VERIFIED" or raw["scope"] == "unresolved"
        ):
            raise LeakageError("Unresolved identifier cannot select copy relationships")
        identifiers.append(
            Identifier(
                cast(str, raw["field"]),
                cast(str, raw["representation"]),
                cast(str, raw["status"]),
                cast(str, raw["scope"]),
                tuple(cast(list[str], raw["verified_sentinels"])),
                tuple(cast(list[str], raw["ambiguous_values"])),
                cast(str, raw["evidence"]),
                raw["copy_eligible"],
            )
        )
    if tuple(i.field for i in identifiers) != ("AlertId", *ENTITY_FIELDS):
        raise LeakageError(
            "G5 registry must inventory the fixed audit-only identifier fields"
        )
    alert = identifiers[0]
    if (
        alert.status,
        alert.scope,
        alert.verified_sentinels,
        alert.ambiguous_values,
        alert.copy_eligible,
    ) != ("VERIFIED", "organization", (), (), True):
        raise LeakageError("Accepted scoped alert identity must remain unchanged")
    return AuditConfig(doc, tuple(identifiers), limits, fingerprint(doc))


def regular(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise LeakageError("Regular non-symlink artifact required")


def verify_inputs(
    g3: Path,
    g4: Path,
    lock: Path,
    schema: Path,
    manifest: Path,
    config: AuditConfig,
    scratch: Path | None,
) -> tuple[Provenance, dict[str, object], dict[str, object]]:
    """Metadata-only when scratch is None; otherwise invokes strict G3 verification."""
    contract = load_provenance(manifest, schema)
    if not contract.ready or contract.accepted != (
        "Category",
        "EntityType",
        "snapshot_local_distinct_alert_count",
    ):
        raise LeakageError("G5 requires the accepted G4 minimum unchanged")
    db, report_path = g3 / "incidents.sqlite3", g3 / "report.json"
    for path in (db, report_path, g4):
        regular(path)
    if any(
        db.with_name(db.name + suffix).exists()
        for suffix in ("-wal", "-shm", "-journal")
    ):
        raise LeakageError("Accepted G3 must be a closed standalone database")
    pins = cast(dict[str, object], config.document["g4"])
    if g4.stat().st_size != pins["report_bytes"] or sha(g4) != pins["report_sha256"]:
        raise LeakageError("G4 report differs from trusted size/SHA-256 pins")
    if (
        sha(report_path) != contract.g3["report_sha256"]
        or db.stat().st_size != contract.g3["database_bytes"]
    ):
        raise LeakageError("G3 report/size differs from accepted pins")
    r3, r4 = read_json(report_path), read_json(g4)
    raw_checks = r4.get("checks")
    if not isinstance(raw_checks, dict):
        raise LeakageError("G4 explicit integrity checks required")
    checks = cast(dict[str, object], raw_checks)
    if (
        r4.get("gate") != "G4"
        or r4.get("status") != "PASSED"
        or r4.get("training_allowed") is not False
        or r4.get("source_verified") is not True
        or r4.get("g5_g8_performed") is not False
        or r4.get("failure") is not None
        or r4.get("max_evidence_rows") is not None
        or set(checks)
        != {
            "candidate_decisions_resolved",
            "minimum_contract",
            "complete_retained_scan",
            "retained_rows_reconciled",
            "retained_incidents_reconciled",
            "distinct_alerts_reconciled",
            "per_alert_fields_complete",
            "source_metadata_unchanged",
        }
        or any(v is not True for v in checks.values())
        or r4.get("g3") != contract.g3
        or r4.get("manifest_sha256") != contract.sha256
        or r4.get("accepted_fields") != list(contract.accepted)
    ):
        raise LeakageError("G4 full validation/manifest/G3 linkage failed")
    code = cast(dict[str, str], r4["code_sha256"])
    expected = {
        "provenance.py",
        "provenance_validation.py",
        "validate_g4.py",
        "incident_snapshot.py",
    }
    if set(code) != expected:
        raise LeakageError("G4 implementation inventory mismatch")
    for name, digest in code.items():
        path = (
            Path(__file__).with_name(name)
            if name != "incident_snapshot.py"
            else Path(__file__).parents[1] / "features" / name
        )
        if sha(path) != digest:
            raise LeakageError("G4 implementation identity mismatch")
    validation = fingerprint(
        {
            k: r4[k]
            for k in (
                "manifest_sha256",
                "g3",
                "limits",
                "max_evidence_rows",
                "code_sha256",
                "checks",
                "statistics",
                "status",
            )
        }
    )
    if (
        validation != pins["validation_sha256"]
        or r4.get("validation_sha256") != validation
    ):
        raise LeakageError("G4 validation fingerprint mismatch")
    s4 = cast(dict[str, object], r4["statistics"])
    if s4.get("unfitted_projection_sha256") != pins["projection_sha256"]:
        raise LeakageError("G4 projection fingerprint mismatch")
    identity = cast(dict[str, object], r3["reconstruction_identity"])
    if (
        r3.get("reconstruction_sha256") != contract.g3["reconstruction_sha256"]
        or cast(dict[str, object], r3["database"])["sha256"]
        != contract.g3["database_sha256"]
        or cast(dict[str, object], identity["configuration"])["version"]
        != "guide-v1-reconstruction-2"
    ):
        raise LeakageError("Exact accepted G3 v2 required")
    lexical = load_contract(schema)
    columns = [
        n for n in lexical.files[0].header if all(n in f.header for f in lexical.files)
    ]
    if r3["common_columns"] != columns:
        raise LeakageError("G3 payload order differs from G2")
    if scratch is not None:
        original = scratch / "original-g3-config.json"
        original.write_text(json.dumps(identity["configuration"]), encoding="utf-8")
        verify_output(g3, lock, schema, original)
    return contract, r3, r4
