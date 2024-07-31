# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import pathlib
import nox

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # type: ignore[import-not-found,no-redef]

nox.options.reuse_existing_virtualenvs = True


def install(
    session: nox.Session,
    *args: str,
    verbose: bool = True,
) -> None:
    if verbose:
        args += ("-v",)
    session.install(
        "-c",
        "ci-constraints-requirements.txt",
        *args,
        silent=False,
    )


def load_pyproject_toml() -> dict:
    with (pathlib.Path(__file__).parent / "pyproject.toml").open("rb") as f:
        return tomllib.load(f)


@nox.session
@nox.session(name="tests-randomorder")
@nox.session(name="tests-nocoverage")
def tests(session: nox.Session) -> None:
    extras = "test"
    if session.name == "tests-randomorder":
        extras += ",test-randomorder"

    install(session, "-e", "./vectors")
    install(session, f".[{extras}]")

    session.run("pip", "list")

    if session.name != "tests-nocoverage":
        cov_args = [
            "--cov=tongsuopy",
            "--cov=tests",
        ]
    else:
        cov_args = []

    if session.posargs:
        tests = session.posargs
    else:
        tests = ["tests/"]

    session.run(
        "pytest",
        "-n",
        "auto",
        "--dist=worksteal",
        *cov_args,
        "--durations=10",
        *tests,
    )

@nox.session
def flake(session: nox.Session) -> None:
    # TODO: Ideally there'd be a pip flag to install just our dependencies,
    # but not install us.
    pyproject_data = load_pyproject_toml()
    install(
        session,
        *pyproject_data["build-system"]["requires"],
        *pyproject_data["project"]["optional-dependencies"]["pep8test"],
        *pyproject_data["project"]["optional-dependencies"]["test"],
        *pyproject_data["project"]["optional-dependencies"]["ssh"],
        *pyproject_data["project"]["optional-dependencies"]["nox"],
    )

    session.run("ruff", "check", ".")
    session.run("ruff", "format", "--check", ".")
    session.run(
        "mypy",
        "src/tongsuopy/",
        "tests/",
        "release.py",
        "noxfile.py",
    )
    session.run("check-sdist", "--no-isolation")


@nox.session(venv_backend="uv")
def local(session):
    pyproject_data = load_pyproject_toml()
    install(
        session,
        *pyproject_data["build-system"]["requires"],
        *pyproject_data["project"]["optional-dependencies"]["pep8test"],
        *pyproject_data["project"]["optional-dependencies"]["test"],
        *pyproject_data["project"]["optional-dependencies"]["ssh"],
        *pyproject_data["project"]["optional-dependencies"]["nox"],
        verbose=False,
    )

    session.run("ruff", "format", ".")
    session.run("ruff", "check", ".")

    session.run(
        "mypy",
        "src/tongsuopy/",
        "tests/",
        "release.py",
        "noxfile.py",
    )

    if session.posargs:
        tests = session.posargs
    else:
        tests = ["tests/"]

    session.run(
        "pytest",
        "-n",
        "auto",
        "--dist=worksteal",
        "--durations=10",
        *tests,
    )
