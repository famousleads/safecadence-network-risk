"""
SafeCadence workflow + governance modules (v10.8).

Modules:
  * ``approval_chains``  — multi-step approvals required before
    :mod:`safecadence.reports.risk_acceptance` accepts a finding.
  * ``soc2_evidence``    — SOC 2 / NIST / HIPAA evidence collection +
    export-as-ZIP. Auto-captures a report-rendered evidence item every
    time a compliance report is generated.
  * ``change_mgmt``      — append-only change log + pluggable hook
    system (Jira/ServiceNow auto-ticket on tracked events).
  * ``pentest``          — pen-test plan + finding + sign-off lifecycle.

All four are persistent on disk under
``~/.safecadence/orgs/<org_id>/`` and require zero new dependencies.
Read-only demo droplets (``SC_READONLY=1``) refuse mutations with a
clear ``PermissionError`` so the public demo can mount the routes
without anyone tampering with state.
"""
