from importlib.metadata import version

import amyntor


def test_package_version_matches_installed_distribution() -> None:
    """The src-layout package must be installed by the development environment."""
    assert amyntor.__version__ == version("amyntor")
