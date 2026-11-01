from __future__ import annotations

import json
import os
import runpy
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from amyntor.data.incident_preflight import storage_preflight


@pytest.mark.parametrize("free,expected", [(607, "BLOCKED"), (608, "READY")])
def test_disk_estimate_includes_database_temporary_and_reserve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, free: int, expected: str
) -> None:
    observed = shutil.disk_usage(tmp_path)._replace(free=free)

    def usage(path: object) -> object:
        return observed

    monkeypatch.setattr(shutil, "disk_usage", usage)
    report = storage_preflight(
        tmp_path,
        tmp_path / "new/output",
        source_bytes=100,
        database_multiplier=4,
        temporary_multiplier=2,
        max_database_bytes=1000,
        minimum_free_bytes=8,
    )
    assert report["status"] == expected
    assert report["estimated_database_bytes"] == 400
    assert report["estimated_temporary_bytes"] == 200
    assert report["required_available_bytes"] == 608
    assert report["source_hashes_verified_by_preflight"] is False
    assert not (tmp_path / "new").exists()


def test_database_cap_blocks_even_with_enough_free_space(tmp_path: Path) -> None:
    report = storage_preflight(
        tmp_path,
        tmp_path / "output",
        source_bytes=100,
        database_multiplier=4,
        temporary_multiplier=2,
        max_database_bytes=399,
        minimum_free_bytes=1,
    )
    assert report["status"] == "BLOCKED"


def test_preflight_checks_output_filesystem_not_input_or_current_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mount = tmp_path / "mounted-input"
    processing = tmp_path / "processing-filesystem"
    mount.mkdir()
    processing.mkdir()
    original = shutil.disk_usage(tmp_path)
    checked: list[Path] = []

    def usage(path: Path) -> object:
        checked.append(path)
        return original._replace(free=1000 if path == processing else 0)

    monkeypatch.setattr(shutil, "disk_usage", usage)
    report = storage_preflight(
        mount,
        processing / "new/full",
        source_bytes=100,
        database_multiplier=4,
        temporary_multiplier=2,
        max_database_bytes=1000,
        minimum_free_bytes=8,
    )
    assert report["status"] == "READY"
    assert checked == [processing]
    assert report["checked_output_filesystem_path"] == str(processing)


def test_thin_entry_point_forwards_configured_paths_to_existing_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = Path(__file__).resolve().parents[2] / "scripts/run_guide_g3_kaggle.py"
    namespace = runpy.run_path(str(script))
    main = cast(Callable[[list[str]], int], namespace["main"])
    received: list[list[str]] = []

    def run(
        command: list[str], *, env: dict[str, str], check: bool
    ) -> subprocess.CompletedProcess[bytes]:
        received.append(command)
        assert check is False
        assert env["PYTHONPATH"].split(os.pathsep)[0] == str(script.parents[1] / "src")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(subprocess, "run", run)
    args = [
        "--files-root",
        str(tmp_path / "mount"),
        "--schema-report",
        str(tmp_path / "g2.json"),
        "--output",
        str(tmp_path / "writable/g3"),
        "--preflight-only",
        "--benchmark-modulus",
        "100",
    ]
    assert main(args) == 0
    assert len(received) == 1
    command = received[0]
    assert command[1:4] == ["-u", "-m", "amyntor.data.reconstruct_guide"]
    assert command[command.index("--files-root") + 1] == str(tmp_path / "mount")
    assert command[command.index("--output") + 1] == str(tmp_path / "writable/g3")
    assert "--preflight-only" in command
    assert command[command.index("--benchmark-modulus") + 1] == "100"
    assert command[command.index("--lock") + 1] == str(
        script.parents[1] / "configs/guide-v1.lock.json"
    )


def test_cli_exposes_preflight_help(capsys: pytest.CaptureFixture[str]) -> None:
    # Public --help is the interface; there is no provider-specific core entry.
    from amyntor.data.reconstruct_guide import main

    with pytest.raises(SystemExit) as stopped:
        main(["--help"])
    assert stopped.value.code == 0
    assert "--preflight-only" in capsys.readouterr().out


def test_preflight_cli_does_not_hash_or_reconstruct(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from amyntor.data.reconstruct_guide import main

    config = (
        Path(__file__).resolve().parents[2] / "configs/guide-v1.reconstruction.json"
    )
    lock = tmp_path / "lock.json"
    lock.write_text(json.dumps({"files": [{"bytes": 1}]}))

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("Storage-only preflight must not inspect/hash corpus files")

    monkeypatch.setattr("amyntor.data.reconstruct_guide.reconstruct", forbidden)
    assert (
        main(
            [
                "--files-root",
                str(tmp_path),
                "--lock",
                str(lock),
                "--contract",
                "unused",
                "--schema-report",
                "unused",
                "--config",
                str(config),
                "--output",
                str(tmp_path / "output"),
                "--preflight-only",
            ]
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "READY"
    assert not (tmp_path / "output").exists()
