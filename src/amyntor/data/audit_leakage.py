"""Thin portable G5 entry point. Full execution requires an explicit flag."""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

from amyntor.data.leakage import audit, preflight
from amyntor.data.leakage_contract import AuditLimit
from amyntor.data.leakage_review import finalize_reviews


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "g3-output",
        "g4-report",
        "lock",
        "schema",
        "manifest",
        "config",
        "scratch",
        "output",
    ):
        parser.add_argument("--" + name, type=Path, required=True)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--preflight-only", action="store_true")
    modes.add_argument("--benchmark-modulus", type=int)
    modes.add_argument("--full", action="store_true")
    modes.add_argument("--review-existing", type=Path)
    parser.add_argument("--prior-report-sha256")
    parser.add_argument("--planning-modulus", type=int)
    parser.add_argument("--reviews", type=Path)
    args = parser.parse_args()
    inputs = (
        args.g3_output,
        args.g4_report,
        args.lock,
        args.schema,
        args.manifest,
        args.config,
        args.scratch,
        args.output,
    )
    try:
        if args.preflight_only:
            report = preflight(*inputs, benchmark_modulus=args.planning_modulus)
            print(json.dumps(report, indent=2, sort_keys=True))
            return 0 if report["feasible"] else 1
        if args.planning_modulus is not None:
            parser.error("--planning-modulus is for metadata preflight only")
        if args.review_existing:
            if not args.prior_report_sha256 or not args.reviews:
                parser.error(
                    "Review-only requires --prior-report-sha256 and cumulative --reviews"
                )
            report = finalize_reviews(
                *inputs, args.review_existing, args.prior_report_sha256, args.reviews
            )
        else:
            report = audit(
                *inputs, benchmark_modulus=args.benchmark_modulus, reviews=args.reviews
            )
        args.output.mkdir(parents=True, exist_ok=True)
        with (args.output / "report.json").open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
        print(
            json.dumps(
                {"gate": "G5", "status": report["status"], "training_allowed": False}
            )
        )
        return 0 if report["status"] in {"PASSED", "PARTIAL"} else 1
    except AuditLimit as error:
        print("G5 INCOMPLETE: " + str(error))
        return 1
    except (ValueError, OSError, KeyError, TypeError, sqlite3.Error) as error:
        print("G5 rejected: " + type(error).__name__)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
