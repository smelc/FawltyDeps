"""Utilities to share among test modules."""

import io
import logging
import os
import subprocess
import sys
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field, replace
from pathlib import Path
from pprint import pformat
from textwrap import dedent
from typing import Any, Optional, Union

from fawltydeps.main import main
from fawltydeps.packages import (
    BasePackageResolver,
    IdentityMapping,
    Package,
    SysPathPackageResolver,
)
from fawltydeps.types import (
    DeclaredDependency,
    Location,
    ParsedImport,
    UndeclaredDependency,
    UnusedDependency,
)

SAMPLE_PROJECTS_DIR = Path(__file__).with_name("sample_projects")

logger = logging.getLogger(__name__)


def dedent_bytes(data: bytes) -> bytes:
    """Like textwrap.dedent(), but for bytes instead of str."""
    text = data.decode(encoding="utf-8", errors="surrogateescape")
    return dedent(text).encode(encoding="utf-8", errors="surrogateescape")


def walk_dir(path: Path) -> Iterator[Path]:
    """Walk a directory structure and yield Path objects for each file within.

    Wrapper around os.walk() that yields Path objects for files found (directly
    or transitively) under the given directory. Directories whose name start
    with a dot are skipped.
    """
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for filename in files:
            yield Path(root, filename)


def assert_unordered_equivalence(actual: Iterable[Any], expect: Iterable[Any]):
    actual_s = sorted(actual)
    expect_s = sorted(expect)
    assert actual_s == expect_s, (
        f"--- EXPECTED ---\n{pformat(expect_s)}\n--- BUT GOT ---\n{pformat(actual_s)}"
    )


def collect_dep_names(deps: Iterable[DeclaredDependency]) -> Iterable[str]:
    return (dep.name for dep in deps)


def imports_factory(*imports: str) -> list[ParsedImport]:
    return [ParsedImport(imp, Location("<stdin>")) for imp in imports]


def deps_factory(*deps: str, path: str = "foo") -> list[DeclaredDependency]:
    """Dependency generator with a common path for all dependencies."""
    return [DeclaredDependency(name=dep, source=Location(Path(path))) for dep in deps]


# There are the packages/imports we expect to be able to resolve via the default
# LocalPackageResolver. See the isolate_default_resolver() fixture for how we
# make this come true.
default_sys_path_env_for_tests = {
    "pip": {"pip"},
    "setuptools": {"setuptools", "pkg_resources", "_distutils_hack"},
    "isort": {"isort"},
    "typing-extensions": {"typing_extensions"},
    "types-setuptools": {"setuptools-stubs", "pkg_resources-stubs"},
    "types-requests": {"requests-stubs"},
}


def resolved_factory(*deps: str) -> dict[str, Package]:
    def make_package(dep: str) -> Package:
        imports = default_sys_path_env_for_tests.get(dep)
        if imports is not None:  # exists in local env
            return Package(dep, imports, SysPathPackageResolver)
        # fall back to identity mapping
        return Package(dep, {Package.normalize_name(dep)}, IdentityMapping)

    return {dep: make_package(dep) for dep in deps}


def ignore_package_debug_info(resolved_deps: dict[str, Package]) -> dict[str, Package]:
    return {
        name: replace(package, debug_info=None)
        for name, package in resolved_deps.items()
    }


def undeclared_factory(*deps: str) -> list[UndeclaredDependency]:
    return [UndeclaredDependency(dep, [Location("<stdin>")]) for dep in deps]


def unused_factory(*deps: str) -> list[UnusedDependency]:
    return [UnusedDependency(dep, [Location(Path("foo"))]) for dep in deps]


def run_fawltydeps_subprocess(
    *args: str,
    config_file: Path = Path(os.devnull),
    to_stdin: Optional[str] = None,
    cwd: Optional[Path] = None,
) -> tuple[str, str, int]:
    """Run FawltyDeps as a subprocess. Designed for integration tests."""
    proc = subprocess.run(
        [sys.executable, "-m", "fawltydeps", f"--config-file={config_file}", *args],
        input=to_stdin,
        capture_output=True,
        text=True,
        check=False,
        cwd=cwd,
    )
    logger.debug(
        f"Run `fawltydeps {' '.join(args)}` returned exit code {proc.returncode}\n"
        f"    ---- STDOUT ----\n{proc.stdout}"
        f"    ---- STDERR ----\n{proc.stderr}"
        "    ----------------"
    )
    return proc.stdout.strip(), proc.stderr.strip(), proc.returncode


def run_fawltydeps_function(
    *args: str,
    config_file: Path = Path(os.devnull),
    to_stdin: Optional[Union[str, bytes]] = None,
    basepath: Optional[Path] = None,
) -> tuple[str, int]:
    """Run FawltyDeps with `main` function. Designed for unit tests.

    Ignores logging output and returns stdout and the exit code
    """
    if isinstance(to_stdin, str):
        to_stdin = to_stdin.encode()
    output = io.StringIO()
    exit_code = main(
        cmdline_args=([str(basepath)] if basepath else [])
        + [f"--config-file={config_file}"]
        + list(args),
        stdin=io.BytesIO(to_stdin or b""),
        stdout=output,
    )

    output_value = output.getvalue()
    logger.debug(
        f"Run `fawltydeps {' '.join(args)}` returned exit code {exit_code}\n"
        f"    ---- STDOUT ----\n{output_value}"
        "    ----------------"
    )
    output.close()
    return output_value.strip(), exit_code


class FakePackageResolver(BasePackageResolver):
    """Fake package resolver to help with below test vectors.

    Simple package resolver implementation that - given a dictionary of Package
    objects (typically from FDTestVector.expect_resolved_deps below) - returns
    these Package objects back via the official BasePackageResolver API methods.
    """

    def __init__(self, packages: dict[str, Package]) -> None:
        self.packages = packages

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.packages!r})"

    def lookup_packages(self, package_names: set[str]) -> dict[str, Package]:
        return {
            name: self.packages[Package.normalize_name(name)]
            for name in package_names
            if Package.normalize_name(name) in self.packages
        }

    def lookup_import(self, import_name: str) -> Iterable[Package]:
        return (p for p in self.packages.values() if import_name in p.import_names)


@dataclass
class FDTestVector:
    """Test vectors for various parts of the FawltyDeps core logic."""

    id: str
    imports: list[ParsedImport] = field(default_factory=list)
    declared_deps: list[DeclaredDependency] = field(default_factory=list)
    ignore_unused: list[str] = field(default_factory=list)
    ignore_undeclared: list[str] = field(default_factory=list)
    resolver: Optional[FakePackageResolver] = None
    expect_resolved_deps: dict[str, Package] = field(default_factory=dict)
    expect_undeclared_deps: list[UndeclaredDependency] = field(default_factory=list)
    expect_unused_deps: list[UnusedDependency] = field(default_factory=list)


test_vectors = [
    FDTestVector("no_imports_no_deps"),
    FDTestVector(
        "one_import_no_deps",
        imports=imports_factory("pandas"),
        expect_undeclared_deps=undeclared_factory("pandas"),
    ),
    FDTestVector(
        "no_imports_one_dep",
        declared_deps=deps_factory("pandas"),
        expect_resolved_deps=resolved_factory("pandas"),
        expect_unused_deps=unused_factory("pandas"),
    ),
    FDTestVector(
        "matched_import_with_dep",
        imports=imports_factory("pandas"),
        declared_deps=deps_factory("pandas"),
        expect_resolved_deps=resolved_factory("pandas"),
    ),
    FDTestVector(
        "mixed_imports_with_unused_and_undeclared_deps",
        imports=imports_factory("pandas", "numpy"),
        declared_deps=deps_factory("pandas", "scipy"),
        expect_resolved_deps=resolved_factory("pandas", "scipy"),
        expect_undeclared_deps=undeclared_factory("numpy"),
        expect_unused_deps=unused_factory("scipy"),
    ),
    FDTestVector(
        "mixed_imports_from_diff_files_with_unused_and_undeclared_deps",
        imports=[
            *imports_factory("pandas"),
            ParsedImport("numpy", Location(Path("my_file.py"), lineno=3)),
        ],
        declared_deps=deps_factory("pandas", "scipy"),
        expect_resolved_deps=resolved_factory("pandas", "scipy"),
        expect_undeclared_deps=[
            UndeclaredDependency(
                "numpy",
                [Location(Path("my_file.py"), lineno=3)],
            )
        ],
        expect_unused_deps=unused_factory("scipy"),
    ),
    FDTestVector(
        "unused_dep_that_is_ignore_unused__not_reported_as_unused",
        declared_deps=deps_factory("pip"),
        ignore_unused=["pip"],
        expect_resolved_deps=resolved_factory("pip"),
    ),
    FDTestVector(
        "used_dep_that_is_ignore_unused__not_reported_as_unused",
        imports=imports_factory("isort"),
        declared_deps=deps_factory("isort"),
        ignore_unused=["isort"],
        expect_resolved_deps=resolved_factory("isort"),
    ),
    FDTestVector(
        "undeclared_dep_that_is_ignore_unused__reported_as_undeclared",
        imports=imports_factory("isort"),
        ignore_unused=["isort"],
        expect_undeclared_deps=undeclared_factory("isort"),
    ),
    FDTestVector(
        "mixed_deps__report_undeclared_and_non_ignored_unused",
        imports=imports_factory("pandas", "numpy"),
        declared_deps=deps_factory("pandas", "isort", "flake8"),
        ignore_unused=["isort"],
        expect_resolved_deps=resolved_factory("pandas", "isort", "flake8"),
        expect_undeclared_deps=undeclared_factory("numpy"),
        expect_unused_deps=unused_factory("flake8"),
    ),
    FDTestVector(
        "undeclared_dep_that_is_ignore_undeclared__not_reported_as_undeclared",
        imports=imports_factory("invalid_import"),
        ignore_undeclared=["invalid_import"],
    ),
    FDTestVector(
        "declared_dep_that_is_ignore_undeclared__not_reported_as_undeclared",
        imports=imports_factory("isort"),
        declared_deps=deps_factory("isort"),
        ignore_undeclared=["isort"],
        expect_resolved_deps=resolved_factory("isort"),
    ),
    FDTestVector(
        "unused_dep_that_is_ignore_undeclared__reported_as_unused",
        declared_deps=deps_factory("isort"),
        ignore_undeclared=["isort"],
        expect_resolved_deps=resolved_factory("isort"),
        expect_unused_deps=unused_factory("isort"),
    ),
    FDTestVector(
        "mixed_deps__report_unused_and_non_ignored_undeclared",
        imports=imports_factory("pandas", "numpy", "not_valid"),
        declared_deps=deps_factory("pandas", "flake8"),
        ignore_undeclared=["not_valid"],
        expect_resolved_deps=resolved_factory("pandas", "flake8"),
        expect_undeclared_deps=undeclared_factory("numpy"),
        expect_unused_deps=unused_factory("flake8"),
    ),
    FDTestVector(
        "mixed_deps__report_only_non_ignored_unused_and_non_ignored_undeclared",
        imports=imports_factory("pandas", "numpy", "not_valid"),
        declared_deps=deps_factory("pandas", "flake8", "isort"),
        ignore_undeclared=["not_valid"],
        ignore_unused=["isort"],
        expect_resolved_deps=resolved_factory("pandas", "flake8", "isort"),
        expect_undeclared_deps=undeclared_factory("numpy"),
        expect_unused_deps=unused_factory("flake8"),
    ),
    FDTestVector(
        "deps_with_diff_name_for_the_same_import",
        declared_deps=[
            DeclaredDependency(name="Pip", source=Location(Path("requirements1.txt"))),
            DeclaredDependency(name="pip", source=Location(Path("requirements2.txt"))),
        ],
        expect_resolved_deps={
            "Pip": Package("pip", {"pip"}, SysPathPackageResolver),
            "pip": Package("pip", {"pip"}, SysPathPackageResolver),
        },
        expect_unused_deps=[
            UnusedDependency("Pip", [Location(Path("requirements1.txt"))]),
            UnusedDependency("pip", [Location(Path("requirements2.txt"))]),
        ],
    ),
    FDTestVector(
        "undeclared_dep_not_found_in_environment_cannot_suggest_candidate_package",
        imports=imports_factory("foo"),
        expect_undeclared_deps=[
            UndeclaredDependency("foo", [Location("<stdin>")], set()),
        ],
    ),
    FDTestVector(
        "undeclared_dep_found_in_environment_suggests_candidate_package",
        imports=imports_factory("foo"),
        resolver=FakePackageResolver(
            {
                "foo_package": Package("foo_package", {"foo"}, SysPathPackageResolver),
            }
        ),
        expect_undeclared_deps=[
            UndeclaredDependency("foo", [Location("<stdin>")], {"foo_package"}),
        ],
    ),
    FDTestVector(
        "undeclared_dep_found_in_environment_multiple_times_suggests_all_candidates",
        imports=imports_factory("foo"),
        resolver=FakePackageResolver(
            {
                "foo1": Package("foo1", {"foo"}, SysPathPackageResolver),
                "foo2": Package("foo2", {"foo", "bar"}, SysPathPackageResolver),
                "baz": Package("baz", {"baz"}, SysPathPackageResolver),
            }
        ),
        expect_undeclared_deps=[
            UndeclaredDependency("foo", [Location("<stdin>")], {"foo1", "foo2"}),
        ],
    ),
    FDTestVector(
        "ignore_unused_with_wildcard__can_match_multiple_deps",
        declared_deps=deps_factory("pytest-foo", "pytest-bar", "not-pytest-baz"),
        ignore_unused=["pytest-*"],
        expect_resolved_deps=resolved_factory(
            "pytest-foo", "pytest-bar", "not-pytest-baz"
        ),
        expect_unused_deps=unused_factory("not-pytest-baz"),
    ),
    FDTestVector(
        "ignore_undeclare_with_wildcard__can_match_multiple_imports",
        imports=imports_factory("foo", "bar", "baz"),
        ignore_undeclared=["*a*"],
        expect_undeclared_deps=undeclared_factory("foo"),
    ),
    FDTestVector(
        "mixed_deps__report_only_non_ignored_unused_with_wildcard",
        imports=imports_factory("foo", "bar", "baz"),
        declared_deps=deps_factory("foo", "foo-stubs", "pytest-bar", "baz"),
        ignore_unused=["pytest-*"],
        expect_resolved_deps=resolved_factory("foo", "foo-stubs", "pytest-bar", "baz"),
        expect_undeclared_deps=undeclared_factory("bar"),
        expect_unused_deps=[],
    ),
]
