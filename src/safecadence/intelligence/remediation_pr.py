"""
v14.1 — AI-drafted remediation PR generator.

Given a finding (and optionally an asset + target vendor), produces a
proposal an operator can review and merge: forward config snippet,
matched rollback (inverse), blast-radius note, and a unified-diff
preview suitable for pasting into a Git PR description or a ticket.

This module does *not* execute anything. The Tier-3 SSH execution
triple-gate (v9.x → v11.x) still owns the actual rollout. This module
is the *drafting* stage that v14 makes one click instead of several
manual diff steps.

How it works
------------

1. The caller hands us a finding dict + asset dict (both already shaped
   by the existing v11.x stores).
2. We pick the vendor-specific config snippet from the existing
   translator table when there's a known recipe for the (vendor,
   finding-family) pair; otherwise we ask the BYO-AI client to draft
   one, *bounded* by the prompt to only emit syntactically-plausible
   commands for the named vendor.
3. We attach the inverse via the existing rollback heuristics so the
   PR description has the safety net pre-staged.
4. The whole thing is rendered as Markdown + a unified-diff block.

When no LLM is configured AND the (vendor, family) pair isn't in the
translator table, we return a structured "needs operator input"
placeholder instead of hallucinating a config — never invents
commands silently.

Public API
----------

* ``draft_remediation_pr(finding, *, asset=None, vendor=None,
                         model=None, timeout=30)`` → dict
"""
from __future__ import annotations

import os
from typing import Any


# --------------------------------------------------------------------------
# Known per-(vendor, family) recipes. Conservative — covers the
# highest-leverage cases. The LLM fallback handles everything else.
# --------------------------------------------------------------------------


_RECIPES: dict[tuple[str, str], dict] = {
    ("cisco_ios", "ssh_open"): {
        "forward": [
            "configure terminal",
            "line vty 0 15",
            " transport input ssh",
            " access-class MGMT-ACL in",
            "end",
            "write memory",
        ],
        "rollback": [
            "configure terminal",
            "line vty 0 15",
            " transport input ssh telnet",
            " no access-class MGMT-ACL in",
            "end",
            "write memory",
        ],
        "rationale": (
            "Restrict VTY SSH access to a named ACL. Rollback restores "
            "prior wide-open transport list."
        ),
    },
    ("cisco_ios", "snmp_default_community"): {
        "forward": [
            "configure terminal",
            "no snmp-server community public",
            "no snmp-server community private",
            "snmp-server community $NEW_COMMUNITY RO MGMT-ACL",
            "end",
            "write memory",
        ],
        "rollback": [
            "configure terminal",
            "no snmp-server community $NEW_COMMUNITY",
            "snmp-server community public RO",
            "end",
            "write memory",
        ],
        "rationale": (
            "Remove default SNMP communities and replace with a named "
            "RO community bound to MGMT-ACL."
        ),
    },
    ("fortigate", "ssh_open"): {
        "forward": [
            "config system interface",
            "  edit \"mgmt\"",
            "    set allowaccess ssh https ping",
            "  end",
            "end",
        ],
        "rollback": [
            "config system interface",
            "  edit \"mgmt\"",
            "    set allowaccess ssh https http ping telnet",
            "  end",
            "end",
        ],
        "rationale": (
            "Constrain mgmt allowaccess to SSH/HTTPS/PING. Rollback "
            "restores the broader access list."
        ),
    },
    ("okta", "user_missing_mfa"): {
        "forward": [
            "# Okta: enable MFA for user $USER",
            "# Admin UI: People → $USER → Reset Multifactor → enroll required factor",
            "# API: POST /api/v1/users/$USER_ID/factors with factorType",
        ],
        "rollback": [
            "# Okta rollback: clear factor enrollment",
            "# API: DELETE /api/v1/users/$USER_ID/factors/$FACTOR_ID",
        ],
        "rationale": "Enroll mandatory MFA factor for the user.",
    },
}


def _pick_recipe(vendor: str, family: str) -> dict | None:
    return _RECIPES.get(((vendor or "").lower(), (family or "").lower()))


def _llm_draft(
    finding: dict, asset: dict, vendor: str,
    *, model: str | None, timeout: int,
) -> dict | None:
    """Ask the BYO-AI client to draft a vendor-specific snippet. Returns
    None when no LLM is configured or anything fails."""
    try:
        from safecadence.ai.client import (
            AIProvider, _call_anthropic, _call_openai, detect_provider,
        )
        prov = detect_provider()
        if prov == AIProvider.NONE:
            return None
    except Exception:
        return None

    title = finding.get("title", "")
    fam = finding.get("family", "")
    sev = finding.get("severity", "")
    host = (asset or {}).get("hostname", "")

    prompt = (
        "You are a network configuration assistant. Draft a vendor-"
        f"specific config snippet for the vendor named {vendor!r} that "
        f"remediates this finding:\n\n"
        f"TITLE: {title}\nFAMILY: {fam}\nSEVERITY: {sev}\nASSET: {host}\n\n"
        "Output rules:\n"
        "1. Use real config syntax for the named vendor; do not invent commands.\n"
        "2. Return TWO blocks separated by the marker '---ROLLBACK---':\n"
        "   - first block: forward commands\n"
        "   - second block: inverse rollback commands\n"
        "3. One command per line. No prose. No markdown.\n"
        "4. If you cannot produce a syntactically valid snippet for this "
        "vendor, return the single line 'INSUFFICIENT_VENDOR_KNOWLEDGE'.\n"
    )
    try:
        if prov == AIProvider.OPENAI:
            txt = _call_openai(
                prompt,
                api_key=os.environ.get("OPENAI_API_KEY", "").strip(),
                model=model or "gpt-4o-mini",
                timeout=timeout,
            )
        elif prov == AIProvider.ANTHROPIC:
            txt = _call_anthropic(
                prompt,
                api_key=os.environ.get("ANTHROPIC_API_KEY", "").strip(),
                model=model or "claude-haiku-4-5-20251001",
                timeout=timeout,
            )
        else:
            return None
    except Exception:
        return None

    if "INSUFFICIENT_VENDOR_KNOWLEDGE" in (txt or ""):
        return None
    if "---ROLLBACK---" not in (txt or ""):
        return None
    forward_block, rollback_block = txt.split("---ROLLBACK---", 1)
    forward = [l.strip() for l in forward_block.splitlines() if l.strip()]
    rollback = [l.strip() for l in rollback_block.splitlines() if l.strip()]
    if not forward or not rollback:
        return None
    return {
        "forward": forward,
        "rollback": rollback,
        "rationale": "Drafted by configured BYO-AI provider; review before applying.",
    }


def _render_pr_body(
    finding: dict, asset: dict, vendor: str, recipe: dict, source: str,
) -> str:
    title = finding.get("title", "untitled")
    sev = finding.get("severity", "unknown")
    host = (asset or {}).get("hostname", "(unspecified)")

    forward_block = "\n".join(recipe["forward"])
    rollback_block = "\n".join(recipe["rollback"])

    diff_lines = ["--- before"]
    diff_lines.extend(f"+{l}" for l in recipe["forward"])
    diff_block = "\n".join(diff_lines)

    return (
        f"# Remediation: {title}\n\n"
        f"**Severity:** {sev}  \n"
        f"**Asset:** `{host}`  \n"
        f"**Vendor:** `{vendor}`  \n"
        f"**Source of recipe:** {source}\n\n"
        f"## Rationale\n\n{recipe.get('rationale', '')}\n\n"
        f"## Forward commands\n\n```\n{forward_block}\n```\n\n"
        f"## Rollback (auto-attached)\n\n```\n{rollback_block}\n```\n\n"
        f"## Preview (unified diff)\n\n```diff\n{diff_block}\n```\n\n"
        "## Safety\n\n"
        "This PR is a *draft*. Nothing has been executed. To apply, run "
        "the change through the existing approval chain + Tier-3 SSH "
        "triple-gate; rollback is pre-attached above and will fire "
        "automatically on execution failure.\n"
    )


def draft_remediation_pr(
    finding: dict,
    *,
    asset: dict | None = None,
    vendor: str | None = None,
    model: str | None = None,
    timeout: int = 30,
) -> dict:
    """Produce a draft remediation PR for the given finding.

    Returns a dict shaped for the wizard / ticket workflow:

        {
          "ok": True/False,
          "vendor": "...",
          "source": "recipe" | "llm" | "needs_operator_input",
          "forward":  [...],
          "rollback": [...],
          "rationale": "...",
          "pr_body_markdown": "...",
          "warnings": [...]
        }

    Never raises.
    """
    warnings: list[str] = []
    v = (vendor or (asset or {}).get("vendor") or "").lower()
    fam = (finding.get("family") or "").lower()

    # 1. Try a known recipe.
    recipe = _pick_recipe(v, fam)
    source = "recipe" if recipe else None

    # 2. Try LLM fallback.
    if recipe is None and v:
        llm_recipe = _llm_draft(finding, asset or {}, v,
                                model=model, timeout=timeout)
        if llm_recipe is not None:
            recipe = llm_recipe
            source = "llm"
            warnings.append("recipe_from_llm_review_required")

    # 3. Bail out cleanly if neither produced anything.
    if recipe is None:
        warnings.append("no_recipe_available")
        return {
            "ok": False,
            "vendor": v or "(unknown)",
            "source": "needs_operator_input",
            "forward": [],
            "rollback": [],
            "rationale": "",
            "pr_body_markdown": (
                f"# Remediation: {finding.get('title', 'untitled')}\n\n"
                f"No automated recipe is available for vendor `{v or '(unknown)'}` "
                f"+ finding family `{fam or '(unknown)'}`, and the BYO-AI "
                "client either declined or isn't configured. Please draft the "
                "fix manually and attach it to the existing approval workflow.\n"
            ),
            "warnings": warnings,
        }

    return {
        "ok": True,
        "vendor": v,
        "source": source,
        "forward": recipe["forward"],
        "rollback": recipe["rollback"],
        "rationale": recipe.get("rationale", ""),
        "pr_body_markdown": _render_pr_body(
            finding, asset or {}, v, recipe, source or "recipe",
        ),
        "warnings": warnings,
    }


__all__ = ["draft_remediation_pr"]
