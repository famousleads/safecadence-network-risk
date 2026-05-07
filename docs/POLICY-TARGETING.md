# SafeCadence — How to apply policy across mixed fleets

This document answers the questions every operator asks once they
have more than one device:

1. *How do I see a device's config and IP info?*
2. *How do I apply a policy — to one device, a group, or the whole fleet?*
3. *What happens when devices are different vendors / types / environments?*
4. *Can the same policy apply when devices differ — and if not, what should I do?*

---

## 1. Where you see device facts

Every asset has a deep-link page at `/asset/{asset_id}` that shows **13
field groups**, populated automatically from auto-discovery, CSV
import, or manual entry:

| # | Group | Source |
|---|---|---|
| 1 | Device identity (hostname, vendor, model, serial, etc.) | `show version`, `show inventory` |
| 2 | Hardware inventory (modules, transceivers, PSU, fans) | `show inventory` |
| 3 | Operating system + boot image + uptime | `show version` |
| 4 | Licensing | `show license summary` |
| 5 | System resources (CPU, memory) | `show processes cpu`, `show memory` |
| 6 | Interfaces (status, IP, MAC, errors) | `show ip int brief`, `show interfaces` |
| 7 | Routing table summary | `show ip route` |
| 8 | ARP / MAC tables | `show arp`, `show mac address-table` |
| 9 | Network security (AAA, SSH/Telnet, ACLs, open ports) | running config |
| 10 | Routing protocols (OSPF, BGP, EIGRP) | `show protocols` |
| 11 | Logs & time (NTP, syslog, log buffer) | `show logging`, `show clock` |
| 12 | Voice / UC | `show voice`, `show sip` |
| 13 | Compliance / risk signals (AI-generated) | derived from above |

Plus a **Running configuration** block with copy + download buttons
near the bottom, and a **Custom fields editor** for any KV pairs you
want to attach (business owner, change window, criticality reason).

> The /asset/{id} page only shows the categories that have populated
> data. A bare-bones imported device might only show Identity + OS.
> A fully-collected device shows everything.

---

## 2. The 4-layer targeting model

A SafeCadence policy targets assets by one or more of these layers,
evaluated in this order:

```
Layer 1: TAGS              (most flexible, scales with the fleet)
Layer 2: ASSET GROUPS      (saved query — names a slice of the fleet)
Layer 3: ASSET TYPE / VENDOR  (vendor-specific syntax concerns)
Layer 4: INDIVIDUAL ASSET  (escape hatch for one-offs)
```

The general rule: **always start at Layer 1. Drop down only when you
have to.**

### Layer 1: Tags

Tags are namespaced strings attached to every asset:

```
role:edge-router
env:prod
site:dc1
criticality:crown-jewel
compliance:pci
vendor:cisco
team:network-eng
```

Tags come from three places:

- **AI auto-enrichment** when an asset is added (role, env, site,
  criticality, compliance tier, owner team)
- **Operator-defined** via the inventory column-picker → custom fields
- **Adapter-defined** when supported by the source

Targeting by tag means **the policy automatically picks up new assets
that match**. Add a new prod database tomorrow → it inherits the
"prod databases must rotate keys quarterly" policy without any human
clicking anything.

### Layer 2: Asset groups

A saved query that names a slice. Groups are first-class objects
operators see in the UI:

```yaml
group: "DC1 crown jewels"
query:
  AND:
    - tag: env:prod
    - tag: site:dc1
    - tag: criticality:crown-jewel
```

Use groups when:

- The slice is named by a business stakeholder ("everything the CFO's
  team owns")
- You want to target the same set with multiple policies
- You want a single "exception list" object to manage

### Layer 3: Asset type / vendor

Used when policy implementation is vendor-specific:

```yaml
target:
  asset_types: [network]
  vendors: [cisco]
```

This is the one place where the policy IR genuinely needs vendor
context — if you're rewriting a Cisco IOS line, you need to know
it's Cisco IOS, not Arista EOS.

### Layer 4: Individual asset

```yaml
target:
  asset_ids: [edge-rtr-01.acme.local]
```

Almost never the right answer. Use when:

- An asset is genuinely unique (the one mainframe)
- You're testing a policy on a single canary
- You're applying a one-time change to a specific device

---

## 3. Mixed fleets — the IR + per-vendor translator pattern

The **Unified Policy IR** is vendor-agnostic. Per-vendor translators
generate the right syntax for each device.

### Example: "telnet is forbidden on production network gear"

You author one IR:

```json
{
  "intent": "telnet is forbidden on production network gear",
  "controls": ["disable_telnet"],
  "targeting": {
    "tags": ["env:prod"],
    "asset_types": ["network"]
  },
  "effect": "enforce",
  "severity": "enforce"
}
```

SafeCadence's translators fan it out into vendor-native commands:

| Vendor / OS | Generated command |
|---|---|
| Cisco IOS | `line vty 0 4 / no transport input telnet` |
| Cisco NX-OS | `no feature telnet` |
| Arista EOS | `management telnet / shutdown` |
| Juniper Junos | `delete system services telnet` |
| Palo Alto PAN-OS | `set deviceconfig system service disable-telnet yes` |
| Aruba ArubaOS | `no telnet server` |
| Fortinet FortiOS | `config system global / unset admin-telnet` |

You see ONE preview. The diff fans out automatically. **You author
once.** No duplicate policies per vendor.

### What if a vendor isn't supported?

Three options:

1. **Add it.** Per-vendor translators are ~50 lines each. PR welcome.
2. **Mark non-applicable.** Policy renders as N/A on that asset and
   doesn't penalize compliance score.
3. **Drop the asset out of targeting.** Add an exclude rule for the
   vendor.

---

## 4. When the same policy can't apply

Three scenarios + the right move for each:

### Scenario A: Different intent per environment

> "Prod must enforce MFA. Dev can rely on SSO only."

**Wrong:** stretch one policy to cover both.

**Right:** two policies. Each targets a different group:

```
Policy P1: "Prod MFA enforcement"   targeting: tags:[env:prod]
Policy P2: "Dev SSO baseline"       targeting: tags:[env:dev]
```

Same fleet, two compliance views, no contradiction.

### Scenario B: A subset of devices can't comply (legacy)

> "All routers must use AAA TACACS+ — except the legacy core that's
> still on local auth and won't move until the 2027 refresh."

**Wrong:** weaken the policy to "AAA TACACS+ OR local auth" → pollutes
the standard for everyone.

**Right:** keep the strict policy, add an **exception** to the
specific asset:

```
Policy: "AAA TACACS+ on all routers"
exceptions:
  - asset_id: legacy-core-rtr-01
    reason: "Vendor doesn't support TACACS+ on this firmware"
    expires_at: "2027-06-30"
    compensating_control: "Bastion-mediated SSH only; no direct mgmt-plane access"
```

The asset shows a yellow exception pill on the dashboard. The pill
disappears automatically on `expires_at`. You're forced to revisit
the exception, not let it rot.

### Scenario C: Policy concept is type-specific

> "Database servers must rotate encryption keys quarterly."

This doesn't apply to network gear at all. Don't try to make it
universal. Target only the relevant type:

```
Policy: "Database key rotation"
targeting:
  AND:
    - tag: role:db-server
    - tag: env:prod
```

Network devices simply don't match — they're not penalized, they're
just not in scope.

---

## 5. The recommended authoring flow

For every new policy you write, follow this order:

```
1. State intent in plain English          ("contractors can't SSH to prod")
2. Pick the broadest targeting that fits   (tags > group > type > id)
3. Translate to IR                          (AI translator or guided form)
4. Preview per-system / per-vendor          (the diff fans out)
5. Simulate                                 (risk delta, closing findings)
6. Identify exceptions                      (assets that legitimately can't)
7. Apply with rollback                      (transactional across systems)
8. Watch the morning briefing               (drift alerts come back)
```

Steps 1-7 take about 5 minutes for a typical policy. SafeCadence
handles the per-vendor explosion. You handle the intent + the
exceptions.

---

## 6. Where to do each step in the UI

| Step | UI page | API endpoint |
|---|---|---|
| 1. Intent | `/identity` (textarea) | `POST /api/identity/translate` |
| 2. Targeting | `/identity` form fields | (in body of translate) |
| 3. IR | `/identity` IR JSON pane | (returned by translate) |
| 4. Preview | `/identity` preview pane | `POST /api/identity/preview` |
| 5. Simulate | `/simulate` | `POST /api/intel/simulate` |
| 6. Exceptions | `/policies` → policy detail | (planned v9.2 — UI hook) |
| 7. Apply | `/identity` apply button | `POST /api/identity/apply` |
| 8. Drift / briefing | `/timeline`, `/briefing` | `GET /api/intel/timeline` |

For non-identity policies (compliance / hardening / network
config), use the legacy compliance builder at `/legacy` for now —
that part of the UI graduates to v9 in a later release.

---

## 7. Examples — concrete fleet, concrete intent

### Example 1 — Mixed-vendor switch hardening

Fleet:
- 12 Cisco IOS access switches
- 8 Arista EOS leaf switches
- 4 Cisco NX-OS spine switches

Intent: *"All access/leaf switches must encrypt all VTY lines
(SSH only) and disable HTTP server."*

Targeting:
```yaml
tags: [role:access-switch, role:leaf-switch]
```

The IR contains two controls: `vty_ssh_only`, `http_server_disabled`.
Translators emit:

- Cisco IOS: `line vty 0 15 / transport input ssh` + `no ip http server`
- Arista EOS: `management telnet / shutdown` + `management api http-commands / no protocol http`
- Cisco NX-OS: matched, `no telnet enable` + `no http enable`

One policy, three vendors, zero duplicate authoring.

### Example 2 — Identity policy across 5 IdPs

Intent: *"Contractors without MFA cannot SSH to production servers."*

Targeting:
```yaml
subjects:
  groups: [Contractors]
resources:
  environments: [prod]
  asset_types: [server]
conditions:
  - mfa_required
effect: deny
targets: [okta, ise, ad, entra, clearpass]
```

The translator emits five operations: Okta group rule, ISE authz rule,
AD group-membership change, Entra Conditional Access policy, ClearPass
enforcement profile + policy. Apply transactionally with rollback.

### Example 3 — Asset-specific exception

Intent: *"All Linux servers must run a CIS-benchmark hardening
profile — except crm-prod-02 which runs a vendor appliance image."*

Targeting:
```yaml
tags: [role:web-server, role:app-server, role:db-server]
asset_types: [server]
exceptions:
  - asset_id: crm-prod-02.acme.local
    reason: "Vendor appliance — image is closed; vendor responsible for hardening"
    expires_at: "2026-12-31"
    compensating_control: "Quarterly vendor SOC 2 attestation reviewed by GRC"
```

`crm-prod-02` shows a yellow exception pill until end of 2026 →
forces re-review.

---

## 8. The mental check — before you write a policy

Ask yourself:

- **Targeting**: am I using tags? If not, is there a tag I should add?
- **Scope**: would this policy still make sense if I had 10× more devices?
- **Vendors**: do all matched assets understand this control? If no,
  I need exceptions or to narrow the target.
- **Exceptions**: which existing devices legitimately can't comply?
  Document them now, not when the audit fails.
- **Drift**: how do I know if someone reverts the change?
  (Answer: SafeCadence's daemon catches it in the next cycle.)

If you can answer all five, the policy is ready to author.

---

## 9. Summary

- **Author intent once**, in plain English. AI translator turns it into
  a vendor-agnostic IR.
- **Target by tag**, not by asset_id. Tags scale; explicit lists rot.
- **Trust the per-vendor translator**. One IR fans out into the
  right CLI per device.
- **Different intents per environment → different policies**, sharing
  asset groups.
- **Exceptions are legitimate** — document them with reason +
  expiry + compensating control; never weaken the policy itself.
- **Exception pills age you** into reviewing them. That's the point.
