# The Community Trust Charter for Public Safety Technology

*Published and self-certified by FamousTec LLC (SafeCadence), Hillsborough
County, Florida. Version 1.0 — August 2026.*

Communities across the country are removing surveillance technology they
no longer trust. The lesson is not that safety technology is bad — it is
that safety technology must be **accountable to the community it
protects**. This Charter states, in plain language, what that means. Each
commitment is written so that anyone — a council member, a defense
attorney, a journalist, a resident — can check whether a vendor actually
meets it. We certify that SafeCadence meets every one, and we show how to
verify each claim on our own product, today. We invite every vendor in
this industry to publish the same certification.

---

## The Seven Commitments

### 1. The community's data stays in the community.
All data — video system events, incidents, evidence records, alerts,
resident registrations — is stored and processed on hardware the agency
owns and controls. No vendor cloud requirement. No telemetry. The vendor
cannot see, sell, share, or subpoena-proxy the community's data, because
the vendor never has it.
**Verify on SafeCadence:** the platform installs from a public package
(`pip install safecadence-publicsafety`) and runs with no vendor account,
no API key, and no outbound connection; even the tactical map renders
on-device.

### 2. No biometric identification. Ever.
No facial recognition. No gait, voice, or other biometric identification.
Not as a feature, not as an add-on, not at any price tier — in writing,
in the product itself.
**Verify on SafeCadence:** the AI Use Policy stating this is displayed
inside the product (Situation Analytics page) and shipped in the source.

### 3. Consent is explicit, recorded, and revocable.
Any program that touches residents — camera registries, community alert
lists — requires each participant's explicit consent, recorded with a
timestamp, revocable at any time. Software must refuse entries without
it.
**Verify on SafeCadence:** attempting to register a community camera or a
community notification recipient without recorded consent is rejected by
the software itself — the API returns an error, not a warning.

### 4. A named human approves every consequential action.
No automated enforcement. No autonomous alerts, lockdowns, or control
actions. Every consequential action carries the name of the human who
approved it — recorded permanently. (Officer-safety timers honor this
rule by capturing the officer's own pre-authorization at the moment they
start the timer.)
**Verify on SafeCadence:** sending any mass notification without a named
approver is refused at the API; the approver's name appears in the
permanent alert log.

### 5. Sensitive operations are provable, not just logged.
Logs can be edited. Provable records cannot. Retention purges, alerts
sent, evidence custody actions, and officer check-ins are written to
hash-chained, tamper-evident logs that anyone with access can
re-verify — including auditors and courts.
**Verify on SafeCadence:** run `safecadence retention verify`,
`safecadence notify verify`, `safecadence custody verify`, or
`safecadence safecheck verify`. Alter any historical line and
verification fails, publicly and loudly.

### 6. Automated alerts are leads, not verdicts.
Machine-generated alerts — license plate reads, video analytics
detections, AI correlations — are presented as leads requiring human
verification, with their confidence and their evidence shown. The
software must say so on the alert itself. (Independent audits have
measured ALPR false-positive rates above 30%; software that hides that
reality endangers both residents and officers.)
**Verify on SafeCadence:** every situation card displays its confidence
and evidence; ALPR-derived cards state on their face that a plate alert
"is a lead, not probable cause."

### 7. Open to inspection, free to leave.
The core platform is open source and publicly auditable. AI policies are
published. The agency's data is exportable in open formats at any time —
leaving the vendor must never mean losing the community's records.
**Verify on SafeCadence:** the core is MIT-licensed on PyPI/GitHub with
2,000+ public automated tests; records are stored as portable JSON/JSONL
and standard formats (GeoJSON export included).

---

## Self-certification

FamousTec LLC certifies that SafeCadence Command complies with all seven
commitments as shipped, and commits to maintaining compliance in every
future release. Where a future feature would conflict with this Charter,
the feature will not be built.

## Model adoption language for communities

Councils, boards, and agencies are welcome to adopt this language:

> *"Before acquiring any public safety technology system, the
> [agency/city/county] shall require the vendor to certify, with
> verifiable evidence, that the system: (1) stores and processes all data
> on infrastructure the agency controls; (2) performs no biometric
> identification; (3) records explicit, revocable consent for any
> resident-facing program; (4) requires a named human approval for every
> consequential action; (5) maintains tamper-evident, re-verifiable
> records of sensitive operations; (6) presents automated alerts as
> leads requiring human verification, with confidence disclosed; and
> (7) provides open, non-proprietary export of all agency data."*

This language is free for any community to use, whether or not it ever
becomes a SafeCadence customer.

## Procurement checklist (for RFP evaluation)

| # | Requirement | Vendor response must include |
|---|---|---|
| 1 | On-premises data custody | Architecture doc + demonstration of offline operation |
| 2 | No biometric identification | Written policy shipped in-product |
| 3 | Recorded, revocable consent | Live demonstration of refusal without consent |
| 4 | Named human approval | Live demonstration of refusal without approver |
| 5 | Tamper-evident records | Verification command run by the evaluator |
| 6 | Alerts-as-leads disclosure | Alert screen showing confidence + disclaimer |
| 7 | Open export, no lock-in | Export demonstration + open-source disclosure |

---

*Questions, challenges, or a vendor who wants to certify:
hello@safecadence.com — a person answers.*
