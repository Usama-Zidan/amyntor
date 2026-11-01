"""Thin environment entry point. All validation/reconstruction stays in the package."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run existing Amyntor G3 on mounted GUIDE"
    )
    parser.add_argument("--files-root", type=Path, required=True)
    parser.add_argument("--schema-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--benchmark-modulus", type=int)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--verify-output", action="store_true")
    args = parser.parse_args(argv)
    if sys.version_info < (3, 12):  # noqa: UP036 - bootstraps before package setup
        parser.error("Amyntor requires Python 3.12 or newer")
    repo = Path(__file__).resolve().parents[1]
    command = [
        sys.executable,
        "-u",
        "-m",
        "amyntor.data.reconstruct_guide",
        "--files-root",
        str(args.files_root),
        "--lock",
        str(repo / "configs/guide-v1.lock.json"),
        "--contract",
        str(repo / "configs/guide-v1.schema.json"),
        "--schema-report",
        str(args.schema_report),
        "--config",
        str(args.config or repo / "configs/guide-v1.reconstruction.json"),
        "--output",
        str(args.output),
    ]
    if args.preflight_only:
        command.append("--preflight-only")
    if args.verify_output:
        command.append("--verify-output")
    if args.benchmark_modulus is not None:
        command.extend(["--benchmark-modulus", str(args.benchmark_modulus)])
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(repo / "src") + (
        os.pathsep + environment["PYTHONPATH"] if environment.get("PYTHONPATH") else ""
    )
    return subprocess.run(command, env=environment, check=False).returncode


if __name__ == "__main__":
    sys.exit(main())
