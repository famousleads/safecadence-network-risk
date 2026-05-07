"""
`safecadence policy ...` CLI subcommand group.

Cross-platform: pure Python + click, all paths via pathlib, all
file I/O explicit utf-8.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from safecadence.policy.audit import read_recent
from safecadence.policy.controls import all_controls
from safecadence.policy.evaluator import evaluate
from safecadence.policy.exporters import export, list_exporters
from safecadence.policy.git_sync import sync as git_sync
from safecadence.policy.interpreter import interpret_offline
from safecadence.policy.remediation import generate_plan
from safecadence.policy.simulator import simulate
from safecadence.policy.shadow_it import find_shadow_assets
from safecadence.policy.store import delete as store_delete, get as store_get, list_policies, save as store_save
from safecadence.policy.templates import list_templates, load_template
from safecadence.policy.testing import run_test_file


@click.group("policy", help="Policy Intelligence Engine — author, evaluate, export.")
def policy_cli():
    pass


@policy_cli.command("templates", help="List bundled policy templates.")
def cmd_templates():
    for t in list_templates():
        click.echo(f"{t['id']:<35} {t['name']}  ({t['control_count']} controls)")


@policy_cli.command("controls", help="List registered controls.")
def cmd_controls():
    for c in all_controls():
        click.echo(f"{c.id:<35} [{c.severity.value:<8}] {c.description}")


@policy_cli.command("list", help="List saved policies.")
def cmd_list():
    pols = list_policies()
    if not pols:
        click.echo("(no policies saved yet)")
        return
    for p in pols:
        click.echo(f"{p['policy_id']:<14} v{p['version']} {p['state']:<8} "
                   f"{p['policy_name']}  ({p['control_count']} controls)")


@policy_cli.command("create", help="Create a policy from a template id.")
@click.option("--template", "-t", required=True, help="Template id, e.g. tmpl_network_hardening")
@click.option("--name", default=None)
@click.option("--owner", default="cli")
def cmd_create(template, name, owner):
    p = load_template(template)
    if not p:
        click.echo(f"unknown template: {template}", err=True); sys.exit(1)
    if name:
        p.policy_name = name
    p.owner = owner
    store_save(p, actor=owner)
    click.echo(f"created {p.policy_id}: {p.policy_name}")


@policy_cli.command("interpret", help="Translate plain English into a policy.")
@click.argument("text", required=False)
@click.option("--from-file", type=click.Path(exists=True, dir_okay=False),
              help="Read text from a file (use '-' for stdin).")
@click.option("--name", default=None)
@click.option("--save", is_flag=True, help="Save the resulting policy to the store.")
@click.option("--ai", is_flag=True,
              help="Use the BYO-AI provider for richer extraction. The offline "
                   "matcher always runs as a safety net so the AI can ADD controls "
                   "but never drop one. Requires SC_AI_PROVIDER (or auto-detect "
                   "from OPENAI_API_KEY / ANTHROPIC_API_KEY / Ollama at localhost).")
@click.option("--provider", default=None,
              type=click.Choice(["openai", "anthropic", "ollama"]),
              help="Override auto-detection (otherwise picked by env vars).")
@click.option("--model", default=None, help="Override the default model.")
def cmd_interpret(text, from_file, name, save, ai, provider, model):
    body = text or ""
    if from_file:
        body = (Path(from_file).read_text(encoding="utf-8")
                if from_file != "-" else sys.stdin.read())
    if not body.strip():
        click.echo("provide TEXT or --from-file", err=True); sys.exit(1)
    from safecadence.policy.interpreter import interpret as _interpret_full
    p = _interpret_full(body, name=name or "", ai=ai, provider=provider, model=model)
    click.echo(f"policy_id: {p.policy_id}  controls: {len(p.controls)}  source: {p.source}")
    for c in p.controls:
        click.echo(f"  - {c.control_id}  {c.parameters or ''}")
    if save:
        store_save(p, actor="cli")
        click.echo(f"saved {p.policy_id}")


@policy_cli.command("delete", help="Delete a policy.")
@click.argument("policy_id")
def cmd_delete(policy_id):
    if store_delete(policy_id, actor="cli"):
        click.echo(f"deleted {policy_id}")
    else:
        click.echo(f"not found: {policy_id}", err=True); sys.exit(1)


@policy_cli.command("evaluate", help="Run a policy against the local platform asset store.")
@click.argument("policy_id")
def cmd_evaluate(policy_id):
    p = store_get(policy_id)
    if not p:
        click.echo(f"not found: {policy_id}", err=True); sys.exit(1)
    assets = _load_assets()
    ev = evaluate(p, assets)
    click.echo(f"pass={ev.pass_count}  fail={ev.fail_count}  na={ev.na_count}  "
               f"coverage={ev.coverage_pct}%")
    for v in ev.violations[:20]:
        click.echo(f"  FAIL {v.asset_id} / {v.control_id}: {v.evidence}")
    if len(ev.violations) > 20:
        click.echo(f"  ... and {len(ev.violations) - 20} more")


@policy_cli.command("simulate", help="What-if: evaluate without persisting.")
@click.argument("policy_id")
def cmd_simulate(policy_id):
    p = store_get(policy_id)
    if not p:
        click.echo(f"not found: {policy_id}", err=True); sys.exit(1)
    res = simulate(p, _load_assets())
    click.echo(json.dumps(res, indent=2))


@policy_cli.command("export", help="Generate remediation in the requested format.")
@click.argument("policy_id")
@click.option("--format", "-f", "fmt", default="markdown",
              type=click.Choice(list_exporters()), show_default=True)
@click.option("--vendor", default=None, help="Force a translator (e.g. cisco_ios).")
@click.option("--out", type=click.Path(dir_okay=False), default=None,
              help="Write to file (default: stdout).")
def cmd_export(policy_id, fmt, vendor, out):
    p = store_get(policy_id)
    if not p:
        click.echo(f"not found: {policy_id}", err=True); sys.exit(1)
    assets = _load_assets()
    ev = evaluate(p, assets)
    plan = generate_plan(p, ev, {(a.get("identity") or {}).get("asset_id", ""): a
                                  for a in assets}, vendor_target=vendor)
    data = export(fmt, p, plan)
    if isinstance(data, bytes):
        if not out:
            click.echo("binary export — use --out to save", err=True); sys.exit(1)
        Path(out).write_bytes(data)
        click.echo(f"wrote {len(data)} bytes to {out}")
        return
    if out:
        Path(out).write_text(data, encoding="utf-8")
        click.echo(f"wrote {len(data)} chars to {out}")
    else:
        click.echo(data)


@policy_cli.command("compliance", help="Cross-policy compliance summary.")
def cmd_compliance():
    assets = _load_assets()
    for meta in list_policies():
        p = store_get(meta["policy_id"])
        if not p:
            continue
        ev = evaluate(p, assets)
        click.echo(f"{p.policy_id:<14} {p.policy_name:<40} "
                   f"pass={ev.pass_count} fail={ev.fail_count} cov={ev.coverage_pct}%")


@policy_cli.command("drift", help="Show drift report for a policy.")
@click.argument("policy_id")
def cmd_drift(policy_id):
    from safecadence.policy.drift import detect_drift
    click.echo(json.dumps(detect_drift(policy_id), indent=2))


@policy_cli.command("shadow", help="List assets covered by no active policy.")
def cmd_shadow():
    sh = find_shadow_assets(_load_assets())
    for a in sh:
        click.echo(f"{a['asset_id'] or '?':<20} {a['vendor'] or '?':<12} "
                   f"{a['asset_type'] or '?':<10} -> {a['reason']}")
    click.echo(f"({len(sh)} shadow assets)")


@policy_cli.command("git-sync", help="Pull policies from a Git repo.")
@click.argument("repo_url")
@click.option("--branch", default="main")
def cmd_git_sync(repo_url, branch):
    res = git_sync(repo_url, branch=branch, actor="cli")
    click.echo(json.dumps(res, indent=2))


@policy_cli.command("test", help="Run policy YAML tests in a directory or file.")
@click.argument("path", type=click.Path(exists=True))
def cmd_test(path):
    p = Path(path)
    results = []
    if p.is_dir():
        from safecadence.policy.testing import run_all_tests
        results = run_all_tests(p)
    else:
        results = run_test_file(p)
    fails = [r for r in results if not r.get("passed")]
    for r in results:
        flag = "PASS" if r.get("passed") else "FAIL"
        click.echo(f"  [{flag}] {r.get('name')}")
        if not r.get("passed"):
            for k, v in (r.get("diffs") or {}).items():
                if v:
                    click.echo(f"     {k}: {v}")
    click.echo(f"{len(results) - len(fails)}/{len(results)} passed")
    if fails:
        sys.exit(1)


@policy_cli.command("audit", help="Show recent audit events.")
@click.option("--limit", default=50, show_default=True)
def cmd_audit(limit):
    for e in read_recent(limit=limit):
        click.echo(f"{e['ts']} {e['actor']:<10} {e['action']:<22} {e.get('policy_id','')}")


# ---- v6.5: per-device diff — "what would change on THIS device" ---- #

@policy_cli.command("diff",
                    help="Show per-device config diff to satisfy a policy.")
@click.argument("policy_id")
@click.argument("asset_id")
@click.option("--json", "as_json", is_flag=True,
              help="Emit the structured payload instead of the rendered text.")
def cmd_policy_diff(policy_id: str, asset_id: str, as_json: bool):
    """Render the line-by-line config changes that would be needed on
    a specific asset to satisfy a saved policy.

    The output shows:
      • Each failing control with severity and the evidence the
        evaluator captured.
      • The vendor-correct fix commands the translator emits, with a
        ✓ next to lines already in the device's running config and a
        + next to lines that need to be added.
      • A unified diff at the bottom that can be reviewed in any
        diff viewer or piped into change-management tooling.
    """
    from safecadence.policy.diff import compute_diff, render_text
    from safecadence.server.platform_api import get_asset
    p = store_get(policy_id)
    if not p:
        click.echo(f"Policy '{policy_id}' not found.", err=True)
        return
    asset = get_asset(asset_id)
    if not asset:
        click.echo(f"Asset '{asset_id}' not found in platform store.",
                   err=True)
        return
    payload = compute_diff(p, asset)
    if as_json:
        click.echo(json.dumps(payload, indent=2, default=str))
    else:
        click.echo(render_text(payload))


# ---- v5.2: scheduler / ATT&CK / executive briefing / gap delta ---- #

@policy_cli.command("schedule", help="Run the policy scheduler — once or as a daemon.")
@click.argument("mode", type=click.Choice(["once", "run"]))
@click.option("--interval", default=3600, show_default=True,
              help="Seconds between cycles (run mode only). Min 60.")
def cmd_schedule(mode, interval):
    from safecadence.policy.scheduler import run_cycle, run_loop
    if mode == "once":
        s = run_cycle(actor="cli")
        click.echo(json.dumps(s, indent=2))
    else:
        run_loop(interval_seconds=interval, actor="cli")


@policy_cli.command("attack-coverage",
                    help="Show ATT&CK technique coverage from active policies.")
def cmd_attack_coverage():
    from safecadence.policy.attack_mapping import coverage_report
    controls = set()
    for meta in list_policies():
        p = store_get(meta["policy_id"])
        if p:
            for c in p.controls:
                controls.add(c.control_id)
    rep = coverage_report(sorted(controls))
    click.echo(f"Controls in use:    {rep['control_count']}")
    click.echo(f"Techniques covered: {rep['techniques_covered']}")
    click.echo(f"Tactics covered:    {rep['tactics_covered']}")
    click.echo()
    for tactic, tids in rep["tactics"].items():
        click.echo(f"  {tactic:<28} {' '.join(tids)}")


@policy_cli.command("briefing", help="Generate an executive security briefing.")
@click.option("--ai", is_flag=True, help="Use BYO-AI provider for richer prose.")
@click.option("--provider", default=None,
              type=click.Choice(["openai", "anthropic", "ollama"]))
@click.option("--out", type=click.Path(dir_okay=False), default=None)
def cmd_briefing(ai, provider, out):
    from safecadence.policy.executive_briefing import build_briefing
    metas = list_policies()
    evals = {}
    from safecadence.policy.evaluator import evaluate as _eval
    assets = _load_assets()
    for meta in metas:
        p = store_get(meta["policy_id"])
        if not p: continue
        ev = _eval(p, assets)
        evals[meta["policy_id"]] = {"pass": ev.pass_count, "fail": ev.fail_count,
                                     "na": ev.na_count, "coverage_pct": ev.coverage_pct}
    b = build_briefing(assets, metas, evals, ai=ai, provider=provider)
    if out:
        Path(out).write_text(b["markdown"], encoding="utf-8")
        click.echo(f"wrote {len(b['markdown'])} chars to {out}  (source: {b['source']})")
    else:
        click.echo(b["markdown"])


@policy_cli.command("chat", help="v6.1 — Conversational AI over fleet inventory + policy state.")
@click.argument("question", required=True)
@click.option("--ai", is_flag=True, help="Use BYO-AI provider (auto-detected from env).")
@click.option("--provider", default=None,
              type=click.Choice(["openai", "anthropic", "ollama"]))
def cmd_chat(question, ai, provider):
    from safecadence.policy.chat_with_fleet import ask
    r = ask(question, ai=ai, provider=provider)
    click.echo(r["answer"])
    click.echo(f"\n(source: {r['source']}, fleet={r['fleet_size']} assets, "
               f"{r['policy_count']} policies)")


@policy_cli.command("ci-check",
                    help="v6.1 — Evaluate every policy and exit non-zero on failure. For CI/CD.")
@click.option("--fail-on-fail/--no-fail-on-fail", default=True)
@click.option("--fail-on-regression/--no-fail-on-regression", default=True)
@click.option("--fail-on-critical", is_flag=True)
@click.option("--fail-on-kev", is_flag=True)
@click.option("--max-fail", type=int, default=None)
@click.option("--format", "-f", "fmt",
              type=click.Choice(["text", "json", "sarif", "junit"]),
              default="text", show_default=True)
@click.option("--out", type=click.Path(dir_okay=False), default=None)
def cmd_ci_check(fail_on_fail, fail_on_regression, fail_on_critical,
                 fail_on_kev, max_fail, fmt, out):
    from safecadence.policy.ci_check import (
        decide_exit_code, evaluate_all,
        render_text, render_sarif, render_junit,
    )
    s = evaluate_all()
    code, reasons = decide_exit_code(
        s, fail_on_fail=fail_on_fail, fail_on_regression=fail_on_regression,
        fail_on_critical=fail_on_critical, fail_on_kev=fail_on_kev,
        max_fail=max_fail,
    )
    if fmt == "text":   body = render_text(s, code, reasons)
    elif fmt == "json": body = json.dumps({**s, "exit_code": code,
                                            "reasons": reasons}, indent=2)
    elif fmt == "sarif": body = render_sarif(s)
    else:               body = render_junit(s)
    if out:
        Path(out).write_text(body, encoding="utf-8")
    else:
        click.echo(body)
    sys.exit(code)


@policy_cli.command("enrichment-package",
                    help="v6.1 — Pack CVE/EOL/EPSS/KEV into a sneakernet bundle.")
@click.argument("out_path", type=click.Path(dir_okay=False))
def cmd_enrich_pack(out_path):
    from safecadence.platform.enrichment_bundle import package
    click.echo(json.dumps(package(out_path), indent=2))


@policy_cli.command("enrichment-import",
                    help="v6.1 — Import an enrichment bundle into the local cache.")
@click.argument("bundle", type=click.Path(exists=True, dir_okay=False))
def cmd_enrich_import(bundle):
    from safecadence.platform.enrichment_bundle import import_bundle
    res = import_bundle(bundle)
    click.echo(json.dumps({k: v for k, v in res.items() if k != "manifest"},
                          indent=2))


@policy_cli.command("fix-top-risks",
                    help="v6.1 — Generate one playbook fixing the top-N highest-priority "
                         "violations across the entire fleet.")
@click.option("--top", default=5, show_default=True, type=int)
@click.option("--format", "-f", "fmt", default="ansible",
              type=click.Choice(["raw", "ansible", "terraform", "powershell",
                                  "bash", "markdown", "pdf"]))
@click.option("--out", type=click.Path(dir_okay=False), default=None)
def cmd_fix_top_risks(top, fmt, out):
    from safecadence.policy.top_risks import fix_top_risks_plan, top_n_violations
    from safecadence.policy.exporters import export
    from safecadence.policy.schema import SecurityPolicy
    assets = _load_assets()
    summary = top_n_violations(assets, top_n=top)
    click.echo(summary["summary"])
    for v in summary["violations"]:
        click.echo(f"  [{v['score']:>4}] {v['asset_id']} / {v['control_id']}  "
                   f"({v['severity']})  policy={v['policy_name']}")
    plan = fix_top_risks_plan(assets, top_n=top)
    synthetic = SecurityPolicy(policy_id="(multi)",
                                policy_name=f"Top {top} risk fixes")
    data = export(fmt, synthetic, plan)
    if out:
        if isinstance(data, bytes):
            Path(out).write_bytes(data)
        else:
            Path(out).write_text(data, encoding="utf-8")
        click.echo(f"\nwrote remediation to {out}")
    else:
        if not isinstance(data, bytes):
            click.echo("\n" + data)


@policy_cli.command("cross-drift",
                    help="v6.0 — Detect policy conflicts across identity, network, cloud.")
def cmd_cross_drift():
    from safecadence.policy.cross_system_drift import detect_all
    res = detect_all(_load_assets())
    click.echo(res["summary"])
    click.echo(f"By severity: {res['by_severity']}")
    for f in res["findings"]:
        click.echo(f"  [{f['severity']:<8}] {f['type']}")
        click.echo(f"           {f['conflict']}")
        click.echo(f"           → {f['resolution']}")


@policy_cli.command("gap-delta",
                    help="Show compliance regressions between the last 2 evaluations of a policy.")
@click.argument("policy_id")
def cmd_gap_delta(policy_id):
    from safecadence.policy.drift import list_evaluations
    from safecadence.policy.executive_briefing import compliance_gap_delta
    history = list_evaluations(policy_id)
    if len(history) < 2:
        click.echo("need at least 2 evaluations — run `safecadence policy evaluate` twice"); return
    history.sort(key=lambda h: h.get("evaluated_at", ""))
    delta = compliance_gap_delta(history[-2], history[-1])
    click.echo(json.dumps(delta, indent=2))


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _load_assets() -> list[dict]:
    """Read the platform asset store written by v3/v4 collectors."""
    base = Path.home() / ".safecadence" / "platform_assets"
    if not base.exists():
        return []
    out = []
    for f in base.glob("*.json"):
        try:
            out.append(json.loads(f.read_text(encoding="utf-8")))
        except Exception:
            continue
    return out
