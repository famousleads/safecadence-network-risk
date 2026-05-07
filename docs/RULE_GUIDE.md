# Rule Authoring Guide

Rules are YAML files. No Python required. New rule packs are the single
highest-leverage contribution to this project.

## Where rules live

```
src/safecadence/data/rules/<vendor_underscores>/<NN>_<topic>.yaml
```

For example: `data/rules/cisco_ios/03_snmp.yaml`. One YAML file may contain
many rules under a top-level list.

## Schema

```yaml
- id: cisco-ios-telnet-enabled       # unique slug — required
  title: Telnet enabled on VTY lines  # short headline — required
  severity: critical                  # critical | high | medium | low | info
  vendor: cisco-ios                   # adapter slug, or "*" for any
  domain: security                    # security | config | availability | performance
  description: |
      Multi-line plain English explanation of the issue and impact.
  remediation: |
      What the operator should do.
  fix_snippet: |
      ! Cisco config that fixes it
      line vty 0 15
       transport input ssh
       no transport input telnet
  references:
      - https://www.cisco.com/...
      - https://nvd.nist.gov/vuln/detail/CVE-XXXX-YYYY

  # === Choose ONE of the three below ===

  match_regex:                          # finding fires if ANY of these match
      - "(?im)^line\\s+vty[\\s\\S]{0,400}?transport\\s+input\\s+[^\\n]*telnet"

  absent_regex:                         # finding fires if NONE of these match
      - "(?im)^\\s*no\\s+ip\\s+source-route"

  custom: |                             # finding fires if expression is True
      bool(re.search(r"(?im)^\s*router\s+ospf", text)) and not bool(re.search(r"(?im)message-digest", text))
```

## Severity guidance

| Severity | Use when… |
|---|---|
| **critical** | Confidentiality / integrity broken. Cleartext credentials, default community strings, RCE-equivalent. |
| **high**     | Significant exposure. Missing auth on routing, no access ACL on management plane. |
| **medium**   | Hardening miss. No NTP, no syslog, default VLAN in use. |
| **low**      | Best-practice nudge. No legal banner, no archive logging. |
| **info**     | Informational only. Doesn't affect score directly. |

## Custom expressions — sandbox

`custom` evaluates Python with `__builtins__` stripped. Available names
inside the expression are `parsed` (the `ParsedConfig` object), `text`
(`parsed.raw_config`), and `re` (the regex module). Anything else will
raise NameError and the rule simply won't fire.

## Testing your rule

Add a sample config exhibiting the issue under
`examples/sample_configs/`, then add a one-line test:

```python
def test_my_rule_fires(findings):
    assert any(f.rule_id == "vendor-my-rule-id" for f in findings)
```

## Style

- Title in noun form ("Telnet enabled on VTY lines"), not imperative.
- Description: 1–3 sentences. State the risk in business terms.
- Remediation: prescriptive, not aspirational.
- `fix_snippet`: copy-paste-ready, valid syntax for that vendor.
- At least one `reference` URL when possible.
