"""v6.1 tests: attack-path viz, top-risks, chat, enrichment bundle, ci-check."""

from __future__ import annotations

import json
import tarfile
from pathlib import Path

import pytest


# --------------------------------------------------------------------------
# 1. Attack-path HTML viz
# --------------------------------------------------------------------------

def test_attack_path_viz_renders_no_cdn():
    from safecadence.platform.attack_paths_viz import render_attack_path_viz
    sample = {"start": "x", "reached": 1, "summary": "demo",
              "paths": [{"asset_id": "a", "asset_type": "server", "hops": 1,
                         "kev_cves": 0,
                         "path": [{"from": "x", "to": "a", "via": "test"}]}]}
    html = render_attack_path_viz(sample)
    assert html.startswith("<!doctype html>")
    assert "<svg" in html
    assert "cdnjs" not in html.lower() and "cdn.jsdelivr" not in html.lower()
    assert "demo" in html  # summary embedded


def test_attack_path_viz_handles_empty():
    from safecadence.platform.attack_paths_viz import render_attack_path_viz
    html = render_attack_path_viz({"start": "x", "reached": 0, "paths": []})
    assert "<svg" in html


# --------------------------------------------------------------------------
# 2. Top-risks
# --------------------------------------------------------------------------

def test_top_n_violations_empty_fleet():
    from safecadence.policy.top_risks import top_n_violations
    r = top_n_violations([], top_n=5)
    assert r["selected"] == 0
    assert r["found"] == 0


def test_top_n_violations_ranks_kev_higher(cisco_router_messy):
    from safecadence.policy.top_risks import top_n_violations
    from safecadence.policy.store import save
    from safecadence.policy.templates import load_template
    p = load_template("tmpl_network_hardening")
    save(p, actor="t")
    asset_dir = Path.home() / ".safecadence" / "platform_assets"
    asset_dir.mkdir(parents=True, exist_ok=True)
    cisco_router_messy["security"] = {"kev_cves": 3, "critical_cves": 1}
    cisco_router_messy["identity"]["criticality"] = "crown-jewel"
    (asset_dir / "r2.json").write_text(json.dumps(cisco_router_messy), encoding="utf-8")
    r = top_n_violations([cisco_router_messy], top_n=3)
    assert r["selected"] >= 1
    # Top-ranked must have a high score (crown-jewel + KEV)
    assert r["violations"][0]["score"] >= 350


def test_fix_top_risks_plan_has_steps(cisco_router_messy):
    from safecadence.policy.top_risks import fix_top_risks_plan
    from safecadence.policy.store import save
    from safecadence.policy.templates import load_template
    save(load_template("tmpl_network_hardening"), actor="t")
    asset_dir = Path.home() / ".safecadence" / "platform_assets"
    asset_dir.mkdir(parents=True, exist_ok=True)
    (asset_dir / "r2.json").write_text(json.dumps(cisco_router_messy), encoding="utf-8")
    plan = fix_top_risks_plan([cisco_router_messy], top_n=5)
    assert plan.summary["total"] >= 1
    assert plan.summary["translated"] >= 1


# --------------------------------------------------------------------------
# 3. Chat with fleet
# --------------------------------------------------------------------------

def test_chat_offline_answers_questions():
    from safecadence.policy.chat_with_fleet import ask
    r = ask("How many assets do I have?")
    assert r["source"] == "offline"
    assert "assets" in r["answer"].lower() or "asset" in r["answer"].lower()


def test_chat_offline_kev_question():
    from safecadence.policy.chat_with_fleet import ask
    r = ask("Show me anything with KEV CVEs")
    assert r["source"] == "offline"
    assert "kev" in r["answer"].lower()


# --------------------------------------------------------------------------
# 4. Enrichment bundle
# --------------------------------------------------------------------------

def test_enrichment_package_round_trip(tmp_path):
    from safecadence.platform.enrichment_bundle import package, import_bundle
    bundle = tmp_path / "enrichment.tar.gz"
    res = package(bundle)
    assert res["ok"]
    assert res["bytes"] > 0
    assert bundle.exists()
    # Round-trip
    imp = import_bundle(bundle)
    assert imp["ok"]
    assert imp["files_imported"] > 0
    # Manifest present
    with tarfile.open(bundle, "r:gz") as tar:
        names = [m.name for m in tar.getmembers()]
        assert "bundle.json" in names


def test_enrichment_import_missing_file():
    from safecadence.platform.enrichment_bundle import import_bundle
    r = import_bundle("/nonexistent/file.tar.gz")
    assert not r["ok"]


# --------------------------------------------------------------------------
# 5. CI/CD policy gate
# --------------------------------------------------------------------------

def test_ci_check_empty_fleet_passes():
    from safecadence.policy.ci_check import decide_exit_code, evaluate_all
    s = evaluate_all()
    code, reasons = decide_exit_code(s)
    assert code == 0
    assert reasons == []


def test_ci_check_fail_on_fail_triggers(cisco_router_messy):
    from safecadence.policy.ci_check import decide_exit_code, evaluate_all
    from safecadence.policy.store import save
    from safecadence.policy.templates import load_template
    save(load_template("tmpl_network_hardening"), actor="t")
    asset_dir = Path.home() / ".safecadence" / "platform_assets"
    asset_dir.mkdir(parents=True, exist_ok=True)
    (asset_dir / "r2.json").write_text(json.dumps(cisco_router_messy), encoding="utf-8")
    s = evaluate_all()
    assert s["total_fail"] > 0
    code, reasons = decide_exit_code(s, fail_on_fail=True)
    assert code == 1
    assert any("policy failures" in r for r in reasons)


def test_ci_check_render_sarif_is_valid_json():
    from safecadence.policy.ci_check import evaluate_all, render_sarif
    s = evaluate_all()
    body = render_sarif(s)
    parsed = json.loads(body)
    assert parsed["version"] == "2.1.0"
    assert parsed["runs"][0]["tool"]["driver"]["name"] == "safecadence-netrisk"


def test_ci_check_render_junit_is_valid_xml():
    from safecadence.policy.ci_check import evaluate_all, render_junit
    body = render_junit(evaluate_all())
    assert body.startswith("<?xml")
    assert "<testsuite" in body and "</testsuite>" in body
