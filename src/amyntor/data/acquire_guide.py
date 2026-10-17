"""G1 command: python -m amyntor.data.acquire_guide --help."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import cast

from amyntor.data.acquisition import (
    AcquisitionError,
    acquire,
    verify_bundle,
    verify_files,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Acquire opaque GUIDE artifacts; G1 only"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    download = commands.add_parser(
        "download", help="Create a new verified acquisition bundle"
    )
    download.add_argument("--config", type=Path, required=True)
    download.add_argument("--output", type=Path, required=True)
    download.add_argument("--expected-archive-sha256")
    download.add_argument("--git-commit", help="Override automatic Git SHA discovery")
    download.add_argument(
        "--environment", default="local", choices=["local", "kaggle", "hf_job", "other"]
    )
    verify = commands.add_parser("verify", help="Rehash an existing bundle offline")
    verify.add_argument("--bundle", type=Path, required=True)
    mounted = commands.add_parser(
        "verify-files",
        help="Verify mounted/local files against a trusted release lock offline",
    )
    mounted.add_argument("--files-root", type=Path, required=True)
    mounted.add_argument("--lock", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "verify-files":
            report = verify_files(cast(Path, args.files_root), cast(Path, args.lock))
            print(json.dumps(report, indent=2, sort_keys=True))
            return 0
        elif args.command == "verify":
            path = verify_bundle(cast(Path, args.bundle))
        else:
            git_commit = cast(str | None, args.git_commit)
            if git_commit is None:
                try:
                    commit = subprocess.run(
                        [
                            "git",
                            "-c",
                            f"safe.directory={Path.cwd().as_posix()}",
                            "rev-parse",
                            "HEAD",
                        ],
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=10,
                    )
                    git_commit = (
                        commit.stdout.strip() if commit.returncode == 0 else "unknown"
                    )
                except (OSError, subprocess.SubprocessError):
                    git_commit = "unknown"
            path = acquire(
                cast(Path, args.config),
                cast(Path, args.output),
                expected_archive_sha256=cast(str | None, args.expected_archive_sha256),
                git_commit=git_commit,
                environment=cast(str, args.environment),
            )
        print(f"G1 only; training blocked. Manifest: {path}")
        return 0
    except (AcquisitionError, OSError, subprocess.SubprocessError) as error:
        # Network exceptions can contain signed redirect URLs. Only invariant
        # errors are safe to render; low-level details stay out of normal output.
        message = (
            str(error) if isinstance(error, AcquisitionError) else type(error).__name__
        )
        print(f"G1 acquisition failed: {message}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
