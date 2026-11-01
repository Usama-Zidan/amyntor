"""G3 storage planning only; a preflight is not source-hash verification."""

from __future__ import annotations

import shutil
from pathlib import Path


def storage_preflight(
    files_root: Path,
    output: Path,
    *,
    source_bytes: int,
    database_multiplier: int,
    temporary_multiplier: int,
    max_database_bytes: int,
    minimum_free_bytes: int,
) -> dict[str, object]:
    parent = output.resolve()
    while not parent.exists():
        parent = parent.parent
    usage = shutil.disk_usage(parent)
    free = usage.free
    database = source_bytes * database_multiplier
    temporary = source_bytes * temporary_multiplier
    required = database + temporary + minimum_free_bytes
    checks = {
        "input_directory_exists": files_root.is_dir(),
        "database_estimate_within_configured_cap": database <= max_database_bytes,
        "available_space_covers_estimate_and_reserve": free >= required,
    }
    return {
        "status": "READY" if all(checks.values()) else "BLOCKED",
        "checks": checks,
        "source_bytes": source_bytes,
        "estimated_database_bytes": database,
        "estimated_temporary_bytes": temporary,
        "minimum_free_bytes": minimum_free_bytes,
        "required_available_bytes": required,
        "available_bytes": free,
        "checked_output_filesystem_path": str(parent),
        "checked_output_filesystem_device": parent.stat().st_dev,
        "checked_output_filesystem_total_bytes": usage.total,
        "basis": "Configurable source-byte multipliers informed by bounded G3 benchmark; planning estimates, not guarantees",
        "source_hashes_verified_by_preflight": False,
    }
