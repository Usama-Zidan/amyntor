"""G2 CLI. No downloads, preprocessing, incident reconstruction or training."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import cast

from amyntor.data.acquisition import AcquisitionError
from amyntor.data.schema import ScanLimits, validate_dataset
from amyntor.data.schema_contract import SchemaError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify and stream GUIDE G2 schema validation"
    )
    parser.add_argument("--files-root", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-seconds", type=int, default=3600)
    parser.add_argument("--max-rows-per-file", type=int)
    args = parser.parse_args(argv)
    root, output = cast(Path, args.files_root), cast(Path, args.output)
    try:
        if output.resolve().is_relative_to(root.resolve()):
            raise SchemaError(
                "Report output must be outside the immutable source directory"
            )

        def progress(name: str, rows: int) -> None:
            print(f"{name}: {rows:,} parsed evidence rows", file=sys.stderr, flush=True)

        report = validate_dataset(
            root,
            cast(Path, args.lock),
            cast(Path, args.contract),
            ScanLimits(
                max_seconds=cast(int, args.max_seconds),
                max_rows_per_file=cast(int | None, args.max_rows_per_file),
            ),
            progress=progress,
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        partial = output.with_suffix(output.suffix + ".tmp")
        try:
            partial.write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            partial.replace(output)
        finally:
            partial.unlink(missing_ok=True)
        print(f"G2 {report['status']}; training blocked. Report: {output}")
        return 0 if report["status"] == "PASSED" else 1
    except (AcquisitionError, SchemaError, OSError) as error:
        message = (
            str(error)
            if isinstance(error, (AcquisitionError, SchemaError))
            else type(error).__name__
        )
        print(f"G2 blocked: {message}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
