"""
v7.9 — Automation engine.

IF/THEN rules that fire on findings. Persisted in
~/.safecadence/intel/automation.json. Daemon evaluates every cycle.
Each fire is recorded with a timestamp so the Timeline + Audit log
both surface it.

Stickiness lever — once a user has 5 active rules running, they can't
turn SafeCadence off without breaking their automation chain.

Rule schema (JSON):
  {
    "rule_id": "r_...",
    "name": "auto-fix stale NHIs",
    "enabled": true,
    "when": {
      "kind": "stale_nhi",
      "severity_at_least": "medium",
      "principal_match": "*"     // optional regex
    },
    "then": [
      {"action": "auto_fix"},
      {"action": "notify_slack", "channel": "#sec-alerts"},
      {"action": "assign", "to": "alice@x"}
    ],
    "rate_limit_seconds": 3600   // don't refire on the same finding within
  }

Actions implemented:
  v7.9:
    auto_fix          — runs the suggested IR through the matching
                          adapter. Honors IR.targets (v9.55). Dry-run by
                          default; opt in to real execution with
                          {"action": "auto_fix", "commit": true}.
    assign            — creates an Assignment for the named user
    notify_log        — appends to ~/.safecadence/intel/automation.log
    notify_slack      — fans out via the v9.43 dispatch_event registry
                          (v9.55: was previously a broken import path)
  v9.55:
    add_to_watchlist  — pins the finding to a watchlist (idempotent)
    add_comment       — drops a comment with the automation rationale
    notify_pagerduty  — fires a PD event with deterministic dedup_key
    notify_webhook    — fans out via the multi-provider webhook
                          registry (Slack/Teams/Discord/etc.)
"""

from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Iterable

from safecadence.intel._store import read, write


_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class AutomationRule:
    rule_id: str
    name: str
    when: dict = field(default_factory=dict)
    then: list[dict] = field(default_factory=list)
    enabled: bool = True
    rate_limit_seconds: int = 3600
    created_at: float = 0.0
    last_fired_at: float = 0.0


def list_rules() -> list[AutomationRule]:
    data = read("automation", {"rules": [], "fires": []})
    return [AutomationRule(**r) for r in (data.get("rules") or [])]


def save_rule(rule: AutomationRule | dict) -> AutomationRule:
    if isinstance(rule, dict):
        if "rule_id" not in rule or not rule["rule_id"]:
            rule["rule_id"] = "r_" + uuid.uuid4().hex[:10]
        rule.setdefault("created_at", time.time())
        rule.setdefault("enabled", True)
        rule.setdefault("rate_limit_seconds", 3600)
        rule.setdefault("when", {})
        rule.setdefault("then", [])
        rule_obj = AutomationRule(**{k: v for k, v in rule.items()
                                      if k in AutomationRule.__dataclass_fields__})
    else:
        rule_obj = rule
        if not rule_obj.rule_id:
            rule_obj.rule_id = "r_" + uuid.uuid4().hex[:10]
        if not rule_obj.created_at:
            rule_obj.created_at = time.time()

    data = read("automation", {"rules": [], "fires": []})
    rules = data.setdefault("rules", [])
    # Replace if exists
    rules = [r for r in rules if r.get("rule_id") != rule_obj.rule_id]
    rules.append(asdict(rule_obj))
    data["rules"] = rules
    write("automation", data)
    return rule_obj


def delete_rule(rule_id: str) -> bool:
    data = read("automation", {"rules": [], "fires": []})
    before = len(data.get("rules") or [])
    data["rules"] = [r for r in (data.get("rules") or [])
                      if r.get("rule_id") != rule_id]
    write("automation", data)
    return len(data["rules"]) < before


def evaluate_rules(findings: Iterable[object], *,
                    apply_actions: bool = True,
                    now: float | None = None,
                    on_action=None) -> list[dict]:
    """Walk the findings; for each rule that matches, fire its actions
    (rate-limited). Returns a list of fire records.

    Parameters
    ----------
    findings    iterable of Finding-like objects (must have severity, kind,
                principal, finding_id, suggested_ir attrs)
    apply_actions  If False, just record what *would* fire (for preview UI).
    on_action   Test seam — callable(action_name, finding, kwargs) -> str.
                If provided, used instead of the real action implementations.
    """
    t = now if now is not None else time.time()
    data = read("automation", {"rules": [], "fires": []})
    rules = [r for r in (data.get("rules") or []) if r.get("enabled")]
    fires_acc: list[dict] = []

    for f in findings:
        for r in rules:
            if not _matches(r.get("when") or {}, f):
                continue
            last = float(r.get("last_fired_at") or 0)
            if last and (t - last) < int(r.get("rate_limit_seconds") or 0):
                continue

            for action in (r.get("then") or []):
                outcome = _do_action(
                    action, f, apply_actions=apply_actions,
                    on_action=on_action,
                )
                fires_acc.append({
                    "fire_id": "f_" + uuid.uuid4().hex[:10],
                    "rule_id": r.get("rule_id"),
                    "rule_name": r.get("name"),
                    "action": action.get("action"),
                    "finding_id": getattr(f, "finding_id", None),
                    "severity": getattr(f, "severity", "info"),
                    "outcome": outcome,
                    "applied": apply_actions,
                    "at": t,
                })
            r["last_fired_at"] = t

    if fires_acc and apply_actions:
        data["rules"] = rules + [r for r in (data.get("rules") or [])
                                  if not r.get("enabled")]
        existing_fires = data.get("fires") or []
        # keep last 500 fires only — automation.json shouldn't bloat
        data["fires"] = (existing_fires + fires_acc)[-500:]
        write("automation", data)

    # v9.45 — dispatch one notification per fired rule so authors hear
    # about their automations through the same channels they configured
    # for everything else (email DM if opted in, channel webhook
    # always, multi-provider fan-out). Skipped when apply_actions is
    # False because that's just a preview.
    if fires_acc and apply_actions:
        try:
            from safecadence.notifier.registry import dispatch_event
            for fire in fires_acc:
                dispatch_event(
                    kind="automation_fired",
                    title=f"Automation fired: {fire.get('rule_name', '')}",
                    summary=(
                        f"Rule {fire.get('rule_name')!r} fired "
                        f"action {fire.get('action')!r} on finding "
                        f"{fire.get('finding_id')}: {fire.get('outcome', '')}"
                    ),
                    severity=str(fire.get("severity", "info")),
                    extra={"rule_id": fire.get("rule_id"),
                            "fire_id": fire.get("fire_id"),
                            "action": fire.get("action"),
                            "finding_id": fire.get("finding_id")},
                    link="/automation",
                    requested_by="automation",
                )
        except Exception:               # pragma: no cover
            # Notification is best-effort — never fail the rule fire
            pass

    return fires_acc


# ---------------------------------------------------------------- internals

def _matches(when: dict, finding: object) -> bool:
    fkind = getattr(finding, "kind", "")
    fsev = getattr(finding, "severity", "")
    fprin = getattr(finding, "principal", "")

    if when.get("kind") and when["kind"] != fkind:
        return False
    if when.get("severity_at_least"):
        if (_SEVERITY_RANK.get(fsev, 0) <
                _SEVERITY_RANK.get(when["severity_at_least"], 0)):
            return False
    if when.get("principal_match"):
        try:
            if not re.search(when["principal_match"], fprin):
                return False
        except re.error:
            return False
    return True


def _do_action(action: dict, finding, *, apply_actions: bool,
                on_action=None) -> str:
    name = action.get("action", "")
    if on_action is not None:
        return on_action(name, finding, action)

    if not apply_actions:
        return "preview-only"

    if name == "auto_fix":
        return _act_auto_fix(finding, action)
    if name == "assign":
        return _act_assign(finding, action)
    if name == "notify_log":
        return _act_notify_log(finding, action)
    if name == "notify_slack":
        return _act_notify_slack(finding, action)
    # v9.55 — expanded action library
    if name == "add_to_watchlist":
        return _act_add_to_watchlist(finding, action)
    if name == "add_comment":
        return _act_add_comment(finding, action)
    if name == "notify_pagerduty":
        return _act_notify_pagerduty(finding, action)
    if name == "notify_webhook":
        return _act_notify_webhook(finding, action)
    return f"unknown action: {name}"


def _act_auto_fix(finding, action: dict | None = None) -> str:
    """v9.55 — honor IR.targets and the action's ``commit`` flag.

    Pre-v9.55 this hardcoded ``OktaAdapter`` and always dry-ran. The
    action schema's documented ``commit=true`` opt-in (from the
    docstring at the top of this module) wasn't actually wired,
    and an IR targeting AD or ISE silently dry-ran against Okta.

    Now:
      * IR.targets[0] picks the right adapter (okta / ise / ad /
        entra / clearpass). 'all' fans out — for safety we still
        only execute the FIRST target and surface a note that the
        rule author should split into per-target rules if they want
        full fan-out.
      * action["commit"] = True flips off dry_run. Default stays
        False so a rule that was just typed in /automation can't
        accidentally mutate a real IdP.
    """
    suggested = getattr(finding, "suggested_ir", None) or {}
    if not suggested:
        return "skipped — no suggested_ir"
    try:
        from safecadence.identity.ir import validate_ir
        ir = validate_ir(suggested)
    except Exception as exc:
        return f"invalid suggested_ir: {exc}"
    target = (ir.targets[0] if ir.targets else "okta")
    fanout_note = ""
    if target == "all":
        # IR says "all targets". We pick okta as the first concrete
        # target and surface a note. If the rule author needs full
        # fan-out, they should split into one rule per target.
        target = "okta"
        fanout_note = " (IR targets='all' → only ran first; split rule for fan-out)"

    adapter_class_by_target = {
        "okta":      ("OktaAdapter",            "stub.okta.local"),
        "ise":       ("CiscoISEAdapter",        "stub.ise.local"),
        "ad":        ("ActiveDirectoryAdapter", "stub-dc.local"),
        "entra":     ("EntraIDAdapter",         "stub.entra.local"),
        "clearpass": ("HPEClearPassAdapter",    "stub.clearpass.local"),
    }
    cls_info = adapter_class_by_target.get(target)
    if not cls_info:
        return f"auto_fix skipped — no adapter for IR target {target!r}"
    cls_name, stub_target = cls_info
    commit = bool((action or {}).get("commit"))
    try:
        from safecadence.platform.adapters import identity_adapters as _idm
        adapter_cls = getattr(_idm, cls_name)
        adapter = adapter_cls(target=stub_target, credentials={})
        adapter.apply_policy(ir, dry_run=not commit)
        mode = "committed" if commit else "dry-ran"
        return f"{mode} auto_fix on {target}{fanout_note}"
    except Exception as exc:
        return f"auto_fix failed: {exc}"


def _act_assign(finding, action) -> str:
    from safecadence.intel.comments import assign
    assignee = action.get("to") or "unassigned"
    try:
        a = assign(
            entity_kind="finding",
            entity_id=getattr(finding, "finding_id", "?"),
            assigned_to=assignee,
            assigned_by="automation",
            note=f"auto-assigned by rule on {finding.severity} {finding.kind}",
        )
        return f"assigned {a.assignment_id} to {assignee}"
    except Exception as exc:
        return f"assign failed: {exc}"


def _act_notify_log(finding, action) -> str:
    import os
    from pathlib import Path
    log_path = Path(os.environ.get("SC_INTEL_HOME",
                                     str(Path.home() / ".safecadence" / "intel"))
                     ) / "automation.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(f"{time.time():.0f} {finding.severity} {finding.kind} "
                 f"{getattr(finding, 'principal', '')}\n")
    return f"appended to {log_path}"


def _act_add_to_watchlist(finding, action) -> str:
    """v9.55 — pin the finding's principal (or its asset) to a
    watchlist so subsequent state changes show up in the briefing
    + watchlist alert path. Idempotent — re-firing the same rule
    on the same finding doesn't create duplicate watches."""
    try:
        from safecadence.intel.watchlists import add_watch
    except Exception:
        return "watchlists module not available"
    user = (action or {}).get("user") or "automation"
    entity_kind = (action or {}).get("entity_kind") or "finding"
    entity_id = ((action or {}).get("entity_id")
                  or getattr(finding, "finding_id", "") or "")
    if not entity_id:
        return "skipped — no entity_id on finding"
    label = ((action or {}).get("label")
              or f"auto: {getattr(finding, 'kind', 'finding')} "
                  f"{getattr(finding, 'principal', '')}".strip())
    try:
        w = add_watch(entity_kind=entity_kind, entity_id=entity_id,
                       label=label, user=user)
        return f"watching {entity_kind}:{entity_id} as {w.watch_id}"
    except Exception as exc:
        return f"add_to_watchlist failed: {exc}"


def _act_add_comment(finding, action) -> str:
    """v9.55 — drop a comment on the finding so the team workflow
    surfaces (Comments + Assignments tab) carry the automation's
    rationale alongside human comments."""
    try:
        from safecadence.intel.comments import add_comment
    except Exception:
        return "comments module not available"
    text = ((action or {}).get("text")
             or f"automation: {getattr(finding, 'kind', '')} on "
                 f"{getattr(finding, 'principal', '')} — "
                 f"severity={getattr(finding, 'severity', '')}")
    user = (action or {}).get("user") or "automation"
    try:
        c = add_comment(entity_kind="finding",
                         entity_id=getattr(finding, "finding_id", "?"),
                         user=user, text=text)
        return f"commented {c.comment_id}"
    except Exception as exc:
        return f"add_comment failed: {exc}"


def _act_notify_pagerduty(finding, action) -> str:
    """v9.55 — fire a PagerDuty event via dispatch_event with high
    severity and the deterministic dedup_key the existing
    notifier.providers.pagerduty adapter understands. The action's
    ``service_key`` arg lets a rule pick a specific PD service when
    the operator has more than one configured."""
    try:
        from safecadence.notifier.registry import dispatch_event
    except Exception:                               # pragma: no cover
        return "notifier registry not available"
    sev = getattr(finding, "severity", "info")
    fid = getattr(finding, "finding_id", "?")
    try:
        dispatch_event(
            kind="finding_critical",
            title=f"PagerDuty: {getattr(finding, 'kind', 'finding')} — "
                    f"{getattr(finding, 'title', fid)}",
            summary=(f"Automation rule paged on finding {fid!r}. "
                       f"Severity: {sev}. Principal: "
                       f"{getattr(finding, 'principal', 'n/a')}"),
            severity=str(sev),
            extra={"service_key": (action or {}).get("service_key", ""),
                    "dedup_key": f"safecadence:automation:{fid}",
                    "finding_id": fid},
            link="/findings",
            requested_by="automation",
        )
        return f"pagerduty event dispatched for {fid}"
    except Exception as exc:
        return f"pagerduty failed: {exc}"


def _act_notify_webhook(finding, action) -> str:
    """v9.55 — fire a generic webhook via the notifier registry. The
    rule author specifies ``webhook_id`` (the registry id from
    /settings#webhooks) or leaves it blank to fan out to every
    matching webhook for the finding's category."""
    try:
        from safecadence.notifier.registry import dispatch_event
    except Exception:                               # pragma: no cover
        return "notifier registry not available"
    sev = getattr(finding, "severity", "info")
    fid = getattr(finding, "finding_id", "?")
    kind = (action or {}).get("category") or "automation_fired"
    try:
        dispatch_event(
            kind=kind,
            title=(f"webhook: {getattr(finding, 'kind', 'finding')} "
                     f"— {getattr(finding, 'title', fid)}"),
            summary=(f"Automation rule fired notify_webhook on "
                       f"finding {fid!r}"),
            severity=str(sev),
            extra={"webhook_id": (action or {}).get("webhook_id", ""),
                    "finding_id": fid,
                    "principal": getattr(finding, "principal", "")},
            link="/findings",
            requested_by="automation",
        )
        return f"webhook dispatched for {fid}"
    except Exception as exc:
        return f"webhook failed: {exc}"


def _act_notify_slack(finding, action) -> str:
    """v9.55 — route through the v9.43 dispatch_event registry instead
    of the never-existed ``safecadence.notifiers.slack`` module. The
    registry handles Slack, Teams, Discord, Mattermost, Rocket.Chat,
    PagerDuty, OpsGenie, ServiceNow, Google Chat, Webex, and generic
    HMAC webhooks via the same fan-out, so a rule author saying
    ``notify_slack`` actually reaches whatever channel is configured
    under ``finding_critical`` (or whichever category the rule maps
    to). The ``channel`` arg is preserved as an extra so per-channel
    routing rules in the webhook registry can branch on it.
    """
    try:
        from safecadence.notifier.registry import dispatch_event
    except Exception:                               # pragma: no cover
        return "notifier registry not available"
    channel = action.get("channel", "")
    sev = getattr(finding, "severity", "info")
    kind = getattr(finding, "kind", "finding")
    title = getattr(finding, "title", "") or kind
    try:
        dispatch_event(
            kind="finding_critical" if sev in ("critical", "high")
                    else "automation_fired",
            title=f"[{str(sev).upper()}] {kind} — {title}",
            summary=(f"Automation rule triggered Slack notification for "
                       f"finding {getattr(finding, 'finding_id', '?')!r}"),
            severity=str(sev),
            extra={"channel": channel,
                    "finding_id": getattr(finding, "finding_id", ""),
                    "finding_kind": kind,
                    "principal": getattr(finding, "principal", "")},
            link="/findings",
            requested_by="automation",
        )
        return f"slack-route dispatched ({channel or 'default channels'})"
    except Exception as exc:
        return f"slack failed: {exc}"
