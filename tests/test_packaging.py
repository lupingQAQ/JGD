"""Packaging contract: installed wheel must include every runtime package."""
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib
from pathlib import Path


def test_new_packages_and_python_floor_are_declared():
    root = Path(__file__).resolve().parent.parent
    data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    packages = set(data["tool"]["setuptools"]["packages"])
    for name in (
        "jgd.contracts",
        "jgd.index",
        "jgd.engine",
        "jgd.security",
        "jgd.adapters",
    ):
        assert name in packages, f"missing package from pyproject: {name}"
    assert data["project"]["requires-python"] == ">=3.10"
    assert any(
        dep.startswith("pytest")
        for dep in data["project"]["optional-dependencies"]["test"]
    )
