"""G3 command: same implementation for local and mounted GUIDE files."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import cast

from amyntor.data.acquisition import AcquisitionError
from amyntor.data.incident_preflight import storage_preflight
from amyntor.data.incidents import (
    ReconstructionError,
    load_config,
    read_json,
    reconstruct,
    verify_output,
)
from amyntor.data.schema_contract import SchemaError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="G3 complete incident reconstruction")
    for name in ("files-root", "lock", "contract", "schema-report", "config", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--benchmark-modulus", type=int)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--verify-output", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.verify_output and args.preflight_only:
            raise ReconstructionError("Choose one of preflight or output verification")
        if args.verify_output and args.benchmark_modulus is not None:
            raise ReconstructionError(
                "Benchmark output cannot satisfy full G3 verification"
            )
        if args.verify_output:
            import json

            print(
                json.dumps(
                    verify_output(args.output, args.lock, args.contract, args.config),
                    indent=2,
                )
            )
            return 0
        if args.preflight_only:
            import json

            config = load_config(args.config)
            lock = read_json(args.lock)
            files = cast(list[dict[str, object]], lock["files"])
            result = storage_preflight(
                args.files_root,
                args.output,
                source_bytes=sum(int(cast(int, f["bytes"])) for f in files),
                database_multiplier=config.database_estimate_multiplier,
                temporary_multiplier=config.temporary_estimate_multiplier,
                max_database_bytes=config.max_database_bytes,
                minimum_free_bytes=config.minimum_free_bytes,
            )
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if result["status"] == "READY" else 2
        report = reconstruct(
            args.files_root,
            args.lock,
            args.contract,
            args.schema_report,
            args.config,
            args.output,
            benchmark_modulus=args.benchmark_modulus,
        )
    except (
        AcquisitionError,
        ReconstructionError,
        SchemaError,
        OSError,
        KeyError,
        TypeError,
    ) as error:
        print(f"G3 blocked: {type(error).__name__}", file=sys.stderr)
        return 2
    print(
        f"G3 {report['status']}; training blocked. Report: {args.output / 'report.json'}"
    )
    return 0 if report["status"] == "PASSED" else 1


if __name__ == "__main__":
    sys.exit(main())
