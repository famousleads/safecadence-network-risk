"""Tests for v11.2 — SDKs, Terraform provider, Docker Compose, Helm chart,
and the OpenAPI export CLI.

Each section verifies file presence + minimal shape correctness. The
heavyweight SDK behavior tests live next to their packages
(``sdk/python/tests/test_sdk_client.py``, ``sdk/js/src/index.test.ts``,
``sdk/go/client_test.go``); this file is the cross-cutting integration
test that ties them into the main ``pytest`` run.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile

import pytest


REPO = pathlib.Path(__file__).resolve().parents[1]


# --------------------------------------------------------------------------
# Python SDK
# --------------------------------------------------------------------------


def test_python_sdk_layout_exists():
    sdk = REPO / "sdk" / "python"
    assert (sdk / "pyproject.toml").exists()
    assert (sdk / "README.md").exists()
    assert (sdk / "safecadence_sdk" / "__init__.py").exists()
    assert (sdk / "safecadence_sdk" / "client.py").exists()
    assert (sdk / "safecadence_sdk" / "exceptions.py").exists()
    assert (sdk / "tests" / "test_sdk_client.py").exists()


def test_python_sdk_pyproject_declares_name_and_version():
    content = (REPO / "sdk" / "python" / "pyproject.toml").read_text()
    assert 'name = "safecadence-sdk"' in content
    assert 'version = "0.1.0"' in content
    assert 'requests' in content


def test_python_sdk_client_invokes_expected_endpoints(monkeypatch):
    """End-to-end mock that the SDK class is wired to the right paths."""
    sys.path.insert(0, str(REPO / "sdk" / "python"))
    try:
        from safecadence_sdk import Client
        from unittest.mock import MagicMock

        # Mock a session that always returns a 200/JSON empty list.
        session = MagicMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {"Content-Type": "application/json"}
        resp.text = "[]"
        resp.content = b"[]"
        resp.json.return_value = []
        session.request.return_value = resp

        c = Client("https://api.example.com", api_key="k", session=session)
        c.list_inventory()
        c.list_reports()
        c.list_templates()
        c.get_findings(severity="critical")
        c.get_compliance_status(framework="nist")

        called_paths = [call.args[1] for call in session.request.call_args_list]
        assert any("/api/v1/inventory" in p for p in called_paths)
        assert any("/api/v1/reports" in p for p in called_paths)
        assert any("/api/reports/templates" in p for p in called_paths)
        assert any("/api/v1/findings" in p for p in called_paths)
        assert any("/api/v1/compliance/status" in p for p in called_paths)
    finally:
        sys.path.pop(0)


# --------------------------------------------------------------------------
# JavaScript SDK
# --------------------------------------------------------------------------


def test_js_sdk_layout_exists():
    sdk = REPO / "sdk" / "js"
    assert (sdk / "package.json").exists()
    assert (sdk / "tsconfig.json").exists()
    assert (sdk / "README.md").exists()
    assert (sdk / "src" / "index.ts").exists()
    assert (sdk / "src" / "types.ts").exists()
    assert (sdk / "src" / "index.test.ts").exists()


def test_js_sdk_package_json_shape():
    pkg = json.loads((REPO / "sdk" / "js" / "package.json").read_text())
    assert pkg["name"] == "@safecadence/sdk"
    assert pkg["version"] == "0.1.0"
    # No runtime deps — only dev deps.
    assert "dependencies" not in pkg or not pkg["dependencies"]


# --------------------------------------------------------------------------
# Go SDK
# --------------------------------------------------------------------------


def test_go_sdk_layout_exists():
    sdk = REPO / "sdk" / "go"
    assert (sdk / "go.mod").exists()
    assert (sdk / "client.go").exists()
    assert (sdk / "types.go").exists()
    assert (sdk / "client_test.go").exists()
    assert (sdk / "README.md").exists()


def test_go_sdk_module_path():
    content = (REPO / "sdk" / "go" / "go.mod").read_text()
    assert "module github.com/famousleads/safecadence-go" in content
    assert "go 1.21" in content


# --------------------------------------------------------------------------
# Terraform provider
# --------------------------------------------------------------------------


def test_terraform_provider_layout_exists():
    tf = REPO / "terraform" / "provider-safecadence"
    assert (tf / "go.mod").exists()
    assert (tf / "main.go").exists()
    assert (tf / "provider.go").exists()
    assert (tf / "resource_safecadence_org.go").exists()
    assert (tf / "resource_safecadence_report_template.go").exists()
    assert (tf / "data_source_safecadence_inventory.go").exists()
    assert (tf / "README.md").exists()


def test_terraform_provider_declares_required_schema():
    content = (REPO / "terraform" / "provider-safecadence" / "provider.go").read_text()
    assert 'api_url' in content
    assert 'api_key' in content
    assert 'safecadence_org' in content
    assert 'safecadence_report_template' in content
    assert 'safecadence_inventory' in content


# --------------------------------------------------------------------------
# Docker Compose
# --------------------------------------------------------------------------


def test_docker_compose_yaml_parses():
    try:
        import yaml  # PyYAML may not be installed; fall back to simple checks.
    except ImportError:
        yaml = None

    text = (REPO / "docker-compose.yml").read_text()
    if yaml is None:
        # Still verify the four services are referenced.
        for svc in ("safecadence:", "redis:", "postgres:", "minio:"):
            assert svc in text, f"missing service {svc}"
        return

    doc = yaml.safe_load(text)
    assert "services" in doc
    svc_names = set(doc["services"].keys())
    assert {"safecadence", "redis", "postgres", "minio"}.issubset(svc_names)


def test_docker_compose_override_example_exists():
    assert (REPO / "docker-compose.override.example.yml").exists()


def test_dockerfile_exposes_8003_and_runs_ui():
    content = (REPO / "Dockerfile").read_text()
    assert "EXPOSE 8003" in content
    assert "ui" in content and "8003" in content


# --------------------------------------------------------------------------
# Helm
# --------------------------------------------------------------------------


def test_helm_chart_layout_exists():
    helm = REPO / "helm" / "safecadence-netrisk"
    assert (helm / "Chart.yaml").exists()
    assert (helm / "values.yaml").exists()
    assert (helm / "templates" / "deployment.yaml").exists()
    assert (helm / "templates" / "service.yaml").exists()
    assert (helm / "templates" / "ingress.yaml").exists()
    # The fourth requested template:
    assert (helm / "templates" / "secret.yaml").exists()
    assert (helm / "README.md").exists()


def test_helm_chart_versions():
    content = (REPO / "helm" / "safecadence-netrisk" / "Chart.yaml").read_text()
    assert "version: 0.1.0" in content
    assert 'appVersion: "11.2.0"' in content


def test_helm_deployment_probes_healthz_detail():
    content = (REPO / "helm" / "safecadence-netrisk" / "templates" / "deployment.yaml").read_text()
    assert "/healthz/detail" in content
    assert "livenessProbe" in content
    assert "readinessProbe" in content


# --------------------------------------------------------------------------
# OpenAPI export CLI
# --------------------------------------------------------------------------


def test_openapi_export_produces_valid_schema():
    """`safecadence openapi export --out <tmp>` produces a JSON file
    with the expected top-level keys + the package version stamped in."""
    try:
        import fastapi  # noqa: F401
    except ImportError:
        pytest.skip("fastapi not installed — openapi export needs the [server] extras")

    with tempfile.TemporaryDirectory() as td:
        out = pathlib.Path(td) / "openapi.json"
        result = subprocess.run(
            [
                sys.executable, "-m", "safecadence.cli",
                "openapi", "export", "--out", str(out),
            ],
            capture_output=True, text=True, cwd=str(REPO),
        )
        # CLI should succeed.
        assert result.returncode == 0, (
            f"openapi export failed:\nstdout={result.stdout}\nstderr={result.stderr}"
        )
        assert out.exists()
        data = json.loads(out.read_text())
        assert "info" in data
        assert "paths" in data
        # The stamp follows the live package version. v11.3+ bumps it
        # forward; we just assert it's the right MAJOR.MINOR family or
        # newer so this test doesn't have to be edited every release.
        assert data["info"]["version"].startswith(("11.2", "11.3", "11.")) or \
            data["info"]["version"] >= "11.2.0"


# --------------------------------------------------------------------------
# Version pin
# --------------------------------------------------------------------------


def test_package_version_bumped_to_11_2_0():
    """v11.2 bumped the package to 11.2.0. v11.3+ continued bumping;
    assert ≥ 11.2.0 so a later release doesn't have to edit this test."""
    from safecadence import __version__
    assert __version__ >= "11.2.0"
