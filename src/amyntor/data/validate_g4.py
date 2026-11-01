"""Portable G4 command. Not a reconstruction, split or training entry point."""

from __future__ import annotations

import argparse
import json
import sqlite3
from dataclasses import replace
from pathlib import Path
from typing import cast

from amyntor.data.provenance import ProvenanceError
from amyntor.data.provenance_validation import ValidationLimits, validate_g4


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("g3-output", "lock", "schema", "manifest", "scratch", "report"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--max-evidence-rows", type=int)
    parser.add_argument("--max-seconds", type=int, default=7200)
    parser.add_argument("--minimum-free-bytes", type=int, default=2147483648)
    args = parser.parse_args()
    if args.report.exists() or args.report.resolve().is_relative_to(
        args.g3_output.resolve()
    ):
        parser.error("Choose a new report outside accepted G3 output")
    try:
        result = validate_g4(
            args.g3_output,
            args.lock,
            args.schema,
            args.manifest,
            args.scratch,
            limits=replace(
                ValidationLimits(),
                max_seconds=args.max_seconds,
                minimum_free_bytes=args.minimum_free_bytes,
            ),
            preflight_only=args.preflight_only,
            max_evidence_rows=args.max_evidence_rows,
        )
    except (ValueError, OSError, KeyError, TypeError, sqlite3.Error) as error:
        message = (
            str(error) if isinstance(error, ProvenanceError) else type(error).__name__
        )
        print("G4 rejected: " + message)
        return 2
    if args.preflight_only:
        print(json.dumps(result, indent=2, sort_keys=True))
        return (
            0
            if result["status"] == "PREFLIGHT_ONLY"
            and cast(dict[str, object], result["preflight"])["feasible"]
            else 1
        )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with args.report.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(
        json.dumps(
            {"gate": "G4", "status": result["status"], "training_allowed": False}
        )
    )
    return 0 if result["status"] == "PASSED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
