import os
import subprocess
import sys
from importlib.metadata import version
from pathlib import Path

import amyntor


def test_package_version_matches_installed_distribution() -> None:
    """The src-layout package must be installed by the development environment."""
    assert amyntor.__version__ == version("amyntor")


def test_source_only_import_without_distribution_metadata(tmp_path: Path) -> None:
    source = Path(__file__).resolve().parents[1] / "src"
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(source)
    result = subprocess.run(
        [
            sys.executable,
            "-S",  # Disable site-packages and editable-install metadata discovery.
            "-c",
            """
from importlib.metadata import PackageNotFoundError, version
try:
    version('amyntor')
except PackageNotFoundError:
    pass
else:
    raise AssertionError('Test must run without installed Amyntor metadata')
import amyntor
import amyntor.data.reconstruct_guide
assert amyntor.__version__ == '0+unknown'
print(amyntor.__file__)
""",
        ],
        env=environment,
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert Path(result.stdout.strip()) == source / "amyntor/__init__.py"
