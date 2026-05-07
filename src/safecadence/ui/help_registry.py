"""
v9.1 — Contextual help registry.

Central source of truth for every help tooltip. Pages put

    <span class="sc-help" data-help="translator-intent"></span>

next to a field, and the chrome's JS turns it into a clickable `?` icon
that opens a popover with the matching entry from this registry.

Each entry:

    title        short label (1 line)
    body         1–3 sentence plain-English explanation
    values       list of accepted values (optional)
    example      a one-liner the user can mimic (optional)
    docs_href    deeper-dive link if applicable (optional)
"""

from __future__ import annotations


HELP = {

    # ===== Killer features (Tier S) =====================================
    "translator-intent": {
        "title": "Intent",
        "body": "Plain-English description of the access policy you want enforced. "
                "Be specific about WHO the policy targets, WHAT action they're "
                "trying to do, and WHERE (which environments / asset types).",
        "values": [],
        "example": "contractors without MFA cannot SSH to prod",
        "docs_href": "/identity",
    },

    "translator-effect": {
        "title": "Effect",
        "body": "What happens when the policy matches a request. "
                "deny blocks it, allow permits it, require_step_up forces MFA "
                "or a trusted device check before allowing.",
        "values": ["deny", "allow", "require_step_up"],
        "example": "deny",
    },

    "translator-targets": {
        "title": "Target systems",
        "body": "Which identity systems should enforce this policy. "
                "Pick the smallest set that covers the action — SSH typically "
                "maps to ['okta', 'ise']; admin portal access to ['entra', 'okta']. "
                "Use 'all' to apply to every connected system.",
        "values": ["okta", "ise", "ad", "entra", "clearpass", "all"],
        "example": "okta, ise",
    },

    "translator-conditions": {
        "title": "Conditions",
        "body": "Additional requirements that must hold for the rule to fire. "
                "Compose multiple conditions with AND.",
        "values": [
            "mfa_required — principal must have MFA enrolled",
            "posture_compliant — device must pass posture check",
            "device_trusted — device must be Azure AD-joined",
            "time_window — only during a specific time range",
            "session_age_max — re-auth required after N minutes",
        ],
    },

    "translator-severity": {
        "title": "Severity",
        "body": "How forcefully the rule is applied once committed. "
                "advisory just records the recommendation; warn shows a banner; "
                "enforce actually blocks the action when the rule fires.",
        "values": ["advisory", "warn", "enforce"],
        "example": "enforce",
    },

    "simulator-input": {
        "title": "Policy IR",
        "body": "Paste a Unified Policy IR (the JSON the translator emits). "
                "The simulator projects its impact against your live fleet "
                "without making any external HTTP/LDAP calls. "
                "Click 'Load demo IR' to fill the box automatically.",
    },

    "simulator-risk-delta": {
        "title": "Risk delta",
        "body": "Net change in attack-path reach-weighted risk if the policy "
                "is applied. Negative numbers are good — they mean attack paths "
                "are severed by the change.",
    },

    "who-can-principal": {
        "title": "Principal",
        "body": "The user or non-human identity (NHI) you're evaluating. "
                "Use the email address for human users, or the NHI ID "
                "(e.g. 'nhi-build-bot') for service accounts.",
        "example": "alice.admin@acme.local",
    },

    "who-can-action": {
        "title": "Action",
        "body": "What the principal is trying to do.",
        "values": ["ssh", "rdp", "http", "https", "read", "write", "admin", "login"],
        "example": "ssh",
    },

    "who-can-resource": {
        "title": "Resource",
        "body": "The asset_id or hostname the principal is trying to access.",
        "example": "dc-01.acme.local",
    },

    "jit-duration": {
        "title": "Duration",
        "body": "How long the JIT grant stays active. After this, the daemon "
                "auto-revokes the access. Keep grants short — JIT is for "
                "exceptions, not steady-state access.",
        "values": ["30m", "1h", "4h", "8h", "1d", "max 14d"],
        "example": "4h",
    },

    "jit-target": {
        "title": "Target IdP",
        "body": "Which identity system enforces the grant. The IdP must have "
                "credentials configured (e.g. OKTA_API_TOKEN env var).",
        "values": ["okta", "ise", "ad", "entra", "clearpass"],
    },

    "jit-reason": {
        "title": "Reason",
        "body": "Audit-trail justification. Required for SOX / SOC2 compliance "
                "when granting time-bounded access.",
        "example": "INC-4321 — incident triage on prod-db",
    },

    # ===== Findings + automation (Tier A) ===============================
    "finding-severity": {
        "title": "Severity",
        "body": "How serious the finding is. critical and high warrant immediate "
                "action; medium can wait a sprint; low is hygiene.",
        "values": ["critical", "high", "medium", "low", "info"],
    },

    "finding-kind": {
        "title": "Finding kind",
        "body": "What category the finding belongs to. Determines which "
                "remediation playbook applies.",
        "values": [
            "stale_nhi — service account unused 90+ days",
            "no_mfa — tenant or principal without MFA enforcement",
            "over_privileged — user in 5+ privileged groups",
            "never_rotated — credential past rotation window",
            "orphan_service_account — owner departed",
        ],
    },

    "automation-when-kind": {
        "title": "Match kind",
        "body": "Run this rule when a finding of this kind appears. "
                "Leave blank to match any kind (combined with severity threshold).",
        "values": [
            "stale_nhi", "no_mfa", "over_privileged",
            "never_rotated", "orphan_service_account", "(any)",
        ],
    },

    "automation-when-severity": {
        "title": "Severity threshold",
        "body": "The minimum severity that triggers the rule. 'medium+' fires "
                "for medium, high, and critical findings.",
        "values": ["any", "low+", "medium+", "high+", "critical"],
    },

    "automation-action": {
        "title": "Action to take",
        "body": "What happens when the rule fires.",
        "values": [
            "auto_fix — run the suggested IR through dry-run on the matching adapter",
            "assign — create an Assignment for the named user",
            "notify_log — append to ~/.safecadence/intel/automation.log",
            "notify_slack — send to your configured Slack channel",
        ],
    },

    "automation-rate-limit": {
        "title": "Rate limit",
        "body": "Don't refire the rule for the same finding within this window. "
                "Default 1 hour. Prevents a noisy finding from spamming your "
                "Slack 100 times.",
        "example": "3600 (1 hour)",
    },

    "watchlist-entity-kind": {
        "title": "What to watch",
        "body": "What kind of entity is being pinned. The daemon detects "
                "changes to the corresponding fields and reports them in your "
                "morning briefing.",
        "values": ["asset", "nhi", "principal", "finding", "policy", "path"],
    },

    "share-scope": {
        "title": "Share scope",
        "body": "What the recipient of the share URL can see. "
                "summary = top-line counts; compliance = policies + drift; "
                "identity = findings + paths; evidence = full SOC2/ISO/NIST view.",
        "values": ["summary", "compliance", "identity", "evidence"],
    },

    "share-ttl": {
        "title": "Token lifetime",
        "body": "How long the share URL is valid. After this, the token expires "
                "and the URL returns 403. Max 90 days.",
        "values": ["1 day", "7 days", "30 days", "max 90 days"],
    },

    # ===== Identity attack paths ========================================
    "path-risk": {
        "title": "Risk score",
        "body": "Reach-weighted risk score: higher means more dangerous. "
                "Computed from path length, edge weights (impersonation > "
                "membership), and terminal asset criticality (crown-jewels score 3×).",
        "values": ["0–4 = informational", "4–7 = elevated", "7+ = critical"],
    },

    "path-chain": {
        "title": "Attack chain",
        "body": "Each → represents an edge in the identity graph. "
                "Common edge types: member_of (human → group), can_impersonate "
                "(principal → principal), can_assume_role (NHI → role), "
                "has_credential_to (group → asset).",
    },

    # ===== Dashboard widgets ============================================
    "compliance-score": {
        "title": "Compliance score",
        "body": "Percent of policy controls that pass across your fleet. "
                "Computed continuously by the daemon from the latest evaluations. "
                "Trend is week-over-week. 80%+ is healthy; below 60% needs attention.",
    },

    "next-3-actions": {
        "title": "Next 3 actions",
        "body": "Auto-prioritized: attack paths > critical findings > policy "
                "fails > drift > active JIT. Click any row to drill into "
                "remediation. Updated on every page load.",
    },

    "live-activity": {
        "title": "Live activity feed",
        "body": "Last 8 events from the last 24 hours: audit log entries, JIT "
                "grants, comments, assignments, automation rule fires. "
                "Auto-refreshes every 60 seconds.",
    },

    # ===== Operational ==================================================
    "demo-data": {
        "title": "Demo data",
        "body": "31 realistic fake assets + 3 NHIs designed to trip every "
                "detector — 13 Domain Admins without MFA, 1 stale NHI, "
                "1 never-rotated, 1 orphan service account. Run "
                "`safecadence demo --clear` to remove.",
    },

    "tier-3-totp": {
        "title": "Tier-3 TOTP challenge",
        "body": "Per-job MFA required for high-risk command execution. "
                "Configure once via 'safecadence admin totp enroll', then "
                "every Tier-3 commit prompts for a 6-digit code.",
    },

    "byo-ai": {
        "title": "BYO-AI key",
        "body": "Set OPENAI_API_KEY, ANTHROPIC_API_KEY, or OLLAMA_HOST. "
                "Your key is read at runtime; it never leaves your machine. "
                "Without a key, AI features fall back to deterministic answers "
                "for common keyword queries.",
    },

    # ===== Inventory ====================================================
    "inventory-sources": {
        "title": "How inventory gets populated",
        "body": "Three sources, all of which can run in parallel: "
                "(1) Auto-discovery scans your network — ARP, mDNS, SNMP, "
                "TLS/HTTP fingerprint. (2) CSV/config upload imports from a "
                "CMDB export or per-device running-configs. (3) Manual entry "
                "for crown-jewels you want tracked immediately. "
                "Adapters can also push assets in via REST.",
        "values": [
            "discover — `safecadence discover --cidr 10.0.0.0/24`",
            "csv-import — `safecadence import-assets fleet.csv`",
            "manual — UI form (v9.2)",
            "adapter — registered platform adapter",
            "api — POST /api/platform/<asset_id>",
        ],
    },
    "inventory-columns": {
        "title": "Custom columns",
        "body": "The default view shows the most common fields. Toggle "
                "additional columns to show CPU, memory, license tier, "
                "OSPF/BGP neighbor counts, open ports, AAA state, and more. "
                "Your selection persists in this browser via localStorage.",
    },

    # ===== Policy targeting + application ===============================
    "policy-targeting": {
        "title": "Policy targeting",
        "body": "How a policy decides which assets it applies to. Four "
                "layers, evaluated in order: tag, asset group, asset_type/vendor, "
                "individual asset. Most policies use tags or groups so they "
                "scale with the fleet. Vendor/type targets are for "
                "vendor-specific syntax. Individual asset targets are for "
                "one-off exceptions.",
        "values": [
            "tag — env:prod AND compliance:pci",
            "asset_group — saved query like 'DC1 crown jewels'",
            "asset_type — only network devices",
            "vendor — only Cisco IOS gear",
            "asset_id — explicit, rarely used",
        ],
        "docs_href": "/policies",
    },
    "policies-on-asset": {
        "title": "Policies that apply",
        "body": "Every saved policy whose targeting matches this asset. "
                "Empty targeting = fleet-wide. Tags + types compose. "
                "Click any policy to see its full IR, the per-vendor change "
                "preview, and the current pass/fail result.",
        "docs_href": "/policies",
    },
    "policies-mixed-fleets": {
        "title": "Mixed-vendor fleets",
        "body": "A policy stores ONE Unified Policy IR. Per-vendor "
                "translators (Cisco IOS, NX-OS, Arista, Palo Alto, Juniper, "
                "Aruba, …) generate the right syntax for each device type "
                "automatically. You author intent once; SafeCadence emits "
                "the right CLI for each device.",
    },
    "policies-exception": {
        "title": "Policy exceptions",
        "body": "Some assets legitimately can't comply (legacy gear, vendor "
                "limitations). Add an exception with a reason + expiry + "
                "compensating control. The asset still appears with a "
                "yellow exception pill so it stays visible without being a "
                "constant alarm.",
    },
}


def help_json() -> str:
    """Render the registry as a JS-embeddable JSON literal.
    Called by the chrome to inline `window.SC_HELP = {...}`."""
    import json
    return json.dumps(HELP, ensure_ascii=False)
