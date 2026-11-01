"""Amyntor package metadata."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__: str = version("amyntor")
except PackageNotFoundError:
    # Source-only execution has no installed distribution version to report.
    __version__ = "0+unknown"
