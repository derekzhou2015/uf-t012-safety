"""
Tests for the Python ecosystem remediation chain.

These cover the silent-dropping regression where a non-canonically installed
package produced no remediation advice, and where ignoring one vulnerability
discarded the remediation advice for the other vulnerabilities of the same
package.

The two input pipelines (manifest parsing and environment scanning) must share
the same package-name canonicalization, and ignore rules must only affect the
single vulnerability they target.
"""

from __future__ import annotations

import io
from unittest.mock import patch

import pytest
from packaging.utils import canonicalize_name

from safety.models import Package, SafetyRequirement
from safety.safety import compute_sec_ver_for_user
from safety.scan.ecosystems.python.dependencies import (
    read_requirements,
    read_virtual_environment_dependencies,
)
from safety.scan.ecosystems.python.main import PythonFile
from safety_schemas.models import (
    ConfigModel,
    FileType,
    IgnoredItemDetail,
    IgnoredItems,
    IgnoreCodes,
    PythonDependency,
    PythonSpecification,
)

PKG = "insecure-package"
NON_CANONICAL = "Insecure_Package"
VERSION = "0.1"

INSECURE_DB = {
    "meta": {"base_domain": "https://pyup.io"},
    "vulnerable_packages": {PKG: ["<1.0", "<0.5"]},
}

INSECURE_FULL_DB = {
    "meta": {
        "base_domain": "https://pyup.io",
        "packages": {
            PKG: {
                "secure_versions": ["1.0", "1.1", "2.0"],
                "insecure_versions": ["0.1", "0.4"],
                "latest_version": "2.0",
                "latest_secure_version": "2.0",
                "more_info_path": "/p/pypi/insecure-package/x/",
            }
        },
    },
    "vulnerable_packages": {
        PKG: [
            {
                "specs": ["<1.0"],
                "advisory": "vuln A advisory",
                "transitive": False,
                "more_info_path": "/v/a/x",
                "fixed_versions": ["1.0"],
                "closest_secure_versions": ["1.0"],
                "affected_versions": ["<1.0"],
                "ids": [{"type": "pyup", "id": "PYUP-A"}],
            },
            {
                "specs": ["<0.5"],
                "advisory": "vuln B advisory",
                "transitive": False,
                "more_info_path": "/v/b/x",
                "fixed_versions": ["0.5"],
                "closest_secure_versions": ["0.5"],
                "affected_versions": ["<0.5"],
                "ids": [{"type": "pyup", "id": "PYUP-B"}],
            },
        ]
    },
}


def _fake_get_from_cache(db_name, skip_time_verification=True):
    if db_name == "insecure.json":
        return INSECURE_DB
    return INSECURE_FULL_DB


def _make_config(ignore_ids, ignore_environment=False):
    config = ConfigModel()
    config.depedendency_vulnerability.ignore_vulnerabilities = IgnoredItems(
        {
            vuln_id: IgnoredItemDetail(
                code=IgnoreCodes.manual, reason="ignored in test"
            )
            for vuln_id in ignore_ids
        }
    )
    # Keep the environment itself from being wholesale ignored so the manual,
    # per-vulnerability ignore semantics can be exercised in isolation.
    config.depedendency_vulnerability.python_ignore.environment_results = (
        ignore_environment
    )
    return config


class _InnerFile:
    def __init__(self, name):
        self.name = str(name)


class _InspectableStub:
    def __init__(self, name):
        self.file = _InnerFile(name)


def _env_dependencies(tmp_path):
    # Recreate a minimal virtualenv layout consumed by the env reader.
    cfg = tmp_path / "pyvenv.cfg"
    cfg.write_text("home = x\n", encoding="utf-8")
    dist_info = (
        tmp_path / "Lib" / "site-packages" / f"{NON_CANONICAL}-{VERSION}.dist-info"
    )
    dist_info.mkdir(parents=True)
    (dist_info / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {NON_CANONICAL}\nVersion: {VERSION}\n",
        encoding="utf-8",
    )
    return list(read_virtual_environment_dependencies(_InspectableStub(cfg)))


def _manifest_dependencies():
    return list(read_requirements(io.StringIO(f"{PKG}=={VERSION}\n"), resolve=False))


def _run(dependencies, file_type, ignore_ids, ignore_environment=False):
    python_file = PythonFile(file_type=file_type, file=io.StringIO("x"))
    python_file.file.name = "requirements.txt"
    with patch(
        "safety.scan.ecosystems.python.main.get_from_cache",
        side_effect=_fake_get_from_cache,
    ):
        python_file.__find_dependency_vulnerabilities__(
            dependencies=dependencies,
            config=_make_config(ignore_ids, ignore_environment),
        )
        python_file.remediate()
    return python_file


def _first_spec(python_file):
    dependency = python_file.dependency_results.dependencies[0]
    return dependency, dependency.specifications[0]


def test_environment_reader_canonicalizes_package_name(tmp_path):
    # AC3: the environment pipeline must normalize the dist-info name the same
    # way the manifest pipeline normalizes requirement names.
    dependencies = _env_dependencies(tmp_path)

    assert len(dependencies) == 1
    dependency = dependencies[0]
    assert dependency.name == canonicalize_name(NON_CANONICAL) == PKG
    assert dependency.specifications[0].name == PKG


def test_manifest_and_environment_pipelines_equivalent_with_ignore(tmp_path):
    # AC1 + AC2: ignoring PYUP-A must leave PYUP-B's remediation in place, and
    # both pipelines must produce identical advice regardless of spelling.
    env_result = _run(
        _env_dependencies(tmp_path),
        FileType.VIRTUAL_ENVIRONMENT,
        ["PYUP-A"],
    )
    manifest_result = _run(
        _manifest_dependencies(),
        FileType.REQUIREMENTS_TXT,
        ["PYUP-A"],
    )

    _, env_spec = _first_spec(env_result)
    _, manifest_spec = _first_spec(manifest_result)

    assert env_spec.remediation is not None
    assert manifest_spec.remediation is not None
    assert (
        env_spec.remediation.vulnerabilities_found
        == manifest_spec.remediation.vulnerabilities_found
        == 1
    )
    assert env_spec.remediation.recommended == manifest_spec.remediation.recommended
    assert (
        env_spec.remediation.other_recommended
        == manifest_spec.remediation.other_recommended
    )
    assert (
        env_spec.remediation.closest_secure.upper
        == manifest_spec.remediation.closest_secure.upper
    )


def test_ignore_only_targets_single_vulnerability(tmp_path):
    # AC2: the ignored vuln is flagged but the sibling vuln is not, and the
    # remediation is computed from the remaining (non-ignored) vulnerability.
    result = _run(
        _env_dependencies(tmp_path),
        FileType.VIRTUAL_ENVIRONMENT,
        ["PYUP-A"],
    )
    _, spec = _first_spec(result)

    flags = {v.vulnerability_id: v.ignored for v in spec.vulnerabilities}
    assert flags == {"PYUP-A": True, "PYUP-B": False}
    assert spec.remediation is not None
    assert spec.remediation.vulnerabilities_found == 1
    assert spec.remediation.recommended is not None


def test_no_ignore_reports_both_vulnerabilities_equivalently(tmp_path):
    # AC1 baseline: without any ignore both pipelines count both vulnerabilities
    # and produce the same remediation advice.
    env_result = _run(
        _env_dependencies(tmp_path),
        FileType.VIRTUAL_ENVIRONMENT,
        [],
    )
    manifest_result = _run(
        _manifest_dependencies(),
        FileType.REQUIREMENTS_TXT,
        [],
    )

    _, env_spec = _first_spec(env_result)
    _, manifest_spec = _first_spec(manifest_result)

    assert env_spec.remediation is not None and manifest_spec.remediation is not None
    assert (
        env_spec.remediation.vulnerabilities_found
        == manifest_spec.remediation.vulnerabilities_found
        == 2
    )
    assert env_spec.remediation.recommended == manifest_spec.remediation.recommended
    assert all(not v.ignored for v in env_spec.vulnerabilities)


def test_non_canonical_manual_dependency_lookup_defended(tmp_path):
    # Defense-in-depth: even if a non-canonical name reaches the remediation
    # stage directly (bypassing the reader normalization), the DB lookups must
    # canonicalize and still produce advice instead of silently returning None.
    dependency = PythonDependency(
        name=NON_CANONICAL,
        version=VERSION,
        specifications=[PythonSpecification(f"{NON_CANONICAL}=={VERSION}")],
        insecure_versions=[],
        secure_versions=[],
        latest_version=None,
        latest_version_without_known_vulnerabilities=None,
        more_info_url=None,
    )
    result = _run([dependency], FileType.REQUIREMENTS_TXT, ["PYUP-A"])
    _, spec = _first_spec(result)

    assert spec.remediation is not None
    assert spec.remediation.vulnerabilities_found == 1
    assert spec.remediation.recommended is not None


@pytest.mark.parametrize("ignored", [set(), {"PYUP-A"}])
def test_remediation_never_dropped_across_ignore_states(tmp_path, ignored):
    # The combination that originally failed: non-canonical install + ignore.
    result = _run(
        _env_dependencies(tmp_path),
        FileType.VIRTUAL_ENVIRONMENT,
        list(ignored),
    )
    _, spec = _first_spec(result)
    assert spec.remediation is not None
    assert spec.remediation.recommended is not None


# ---------------------------------------------------------------------------
# Legacy `safety check` pipeline regression coverage (same canonicalization bug)
# ---------------------------------------------------------------------------


def _legacy_db():
    # Keys use the PEP 503 normalized spelling.
    return {
        "meta": {
            "base_domain": "https://pyup.io",
            "packages": {
                PKG: {
                    "secure_versions": ["1.0", "1.1", "2.0"],
                    "insecure_versions": ["0.1", "0.4"],
                    "latest_version": "2.0",
                    "latest_secure_version": "2.0",
                    "more_info_path": "/p/pypi/insecure-package/x/",
                }
            },
        },
        "vulnerable_packages": {
            PKG: [
                {
                    "ids": [{"type": "pyup", "id": "PYUP-A"}],
                    "affected_versions": ["<1.0"],
                },
                {
                    "ids": [{"type": "pyup", "id": "PYUP-B"}],
                    "affected_versions": ["<0.5"],
                },
            ]
        },
    }


def test_legacy_package_get_versions_canonicalizes_name():
    db_full = _legacy_db()
    canonical = Package(
        name=PKG,
        version=VERSION,
        requirements=[SafetyRequirement(f"{PKG}=={VERSION}")],
    )
    non_canonical = Package(
        name=NON_CANONICAL,
        version=VERSION,
        requirements=[SafetyRequirement(f"{NON_CANONICAL}=={VERSION}")],
    )

    expected = {"0.1", "0.4", "1.0", "1.1", "2.0"}
    assert canonical.get_versions(db_full) == expected
    # Before the fix this returned an empty set for the non-canonical spelling.
    assert non_canonical.get_versions(db_full) == expected


def test_legacy_compute_sec_ver_for_user_canonicalizes_name():
    db_full = _legacy_db()
    non_canonical = Package(
        name=NON_CANONICAL,
        version=VERSION,
        requirements=[SafetyRequirement(f"{NON_CANONICAL}=={VERSION}")],
    )
    canonical = Package(
        name=PKG,
        version=VERSION,
        requirements=[SafetyRequirement(f"{PKG}=={VERSION}")],
    )

    # PYUP-A ignored: only PYUP-B's affected versions should narrow the set,
    # regardless of how the package name is spelled.
    result_non_canonical = compute_sec_ver_for_user(
        package=non_canonical,
        secure_vulns_by_user={"PYUP-A"},
        db_full=db_full,
    )
    result_canonical = compute_sec_ver_for_user(
        package=canonical,
        secure_vulns_by_user={"PYUP-A"},
        db_full=db_full,
    )

    assert result_non_canonical == result_canonical
    assert result_non_canonical  # not empty: advice is not silently dropped
