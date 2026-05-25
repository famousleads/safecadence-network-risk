# White-label theming guide

How to ship SafeCadence under your brand for your customers without
forking the code.

> This is for MSPs, resellers, and managed service providers who want
> their customers to see *their* brand at the top of the operator
> portal and customer portal. The underlying SafeCadence platform
> stays MIT-licensed; you're paying us (or anyone) for support, not
> for the right to rebrand.

---

## What's customizable today

Three surfaces support direct theming via env vars (no code changes):

| Surface | What you can change |
|---|---|
| Operator UI chrome | Brand name in topbar, accent color, optional logo SVG |
| Customer portal (`/customer/*`) | Org display name, brand color (per-org) |
| Generated reports | Cover logo, accent color, footer text, "Prepared by" |

## Operator UI chrome

```bash
SC_BRAND_NAME="Acme MSP"
SC_BRAND_ACCENT="#0ea5e9"           # any hex; drives links + active nav
SC_BRAND_LOGO_SVG_PATH=/etc/acme/logo.svg
SC_BRAND_FOOTER="© 2026 Acme MSP — Powered by SafeCadence"
```

When set, the `_chrome.py` shell:
- Shows `SC_BRAND_NAME` in the topbar instead of "SafeCadence"
- Recolors every accent (links, active nav item, primary buttons) to `SC_BRAND_ACCENT`
- Inserts the logo SVG inline at the top of the sidebar (must be a small SVG; 32px high recommended)
- Shows the footer text on every page

The "Powered by SafeCadence" attribution is **mandatory** when
running for paying customers under the MIT license — keep it in the
footer.

## Customer portal (per-org)

The customer portal at `/customer/*` already supports per-org
branding via the `org` dict passed to its renderers
(`safecadence.portal.customer_ui`). Each org row in the
`multitenant.orgs` table carries:

- `display_name` — shown in the topbar
- `brand_color`  — optional hex color (defaults to your `SC_BRAND_ACCENT`)

So a single SafeCadence install can serve `customer-a.example.com`
in Acme blue and `customer-b.example.com` in Beta green from the
same process, without any code changes.

## Generated reports

The report wizard's cover + footer pull from:

```bash
SC_REPORT_LOGO_PATH=/etc/acme/report-logo.png
SC_REPORT_PREPARED_BY="Acme MSP — Security Practice"
SC_REPORT_FOOTER="acme-msp.example.com · soc@acme-msp.example.com"
```

These flow through `reports.renderers` cover-page builder; PDF,
DOCX, and PPTX all pick them up.

## What's NOT theming (and why)

We deliberately don't:

- **Rebrand the CLI binary** (`safecadence`). The CLI is operator-
  facing; if your team needs to know which underlying platform they're
  running, the upstream name should stay.
- **Replace the package name** (`safecadence-netrisk`). Pip
  consistency matters; if your installer ships a custom downstream
  package, brand it as `acme-netrisk-safecadence` so the lineage is clear.
- **Hide the MIT license**. The `LICENSE` file must be redistributed
  unchanged.

## Reseller / VAR considerations

If you're billing your customers separately from SafeCadence support:

- Your customer contracts can name you as the service provider —
  SafeCadence doesn't need to appear.
- Your invoicing flows through your own Stripe / accounting — not ours.
- Your customer support tickets land in your queue first; you escalate
  to upstream SafeCadence support per your support contract terms.
- You can host your own demo at `safecadence.acme-msp.example.com`
  with full visual rebranding using the env vars above.

## Plugin compatibility

White-label customers can also install third-party plugins via the
v15.0 plugin loader (entry-point group `safecadence.plugins`). Those
plugins inherit the brand theming automatically — they just call the
existing UI renderers.

---

## Quick start (15 minutes)

```bash
# 1. Set the four operator-UI env vars
export SC_BRAND_NAME="Acme MSP"
export SC_BRAND_ACCENT="#0ea5e9"
export SC_BRAND_LOGO_SVG_PATH=/etc/acme/logo.svg
export SC_BRAND_FOOTER="© 2026 Acme MSP — Powered by SafeCadence"

# 2. Restart
systemctl restart safecadence

# 3. Visit https://your-domain.example.com/home — see Acme blue + logo.

# 4. For each customer org, set per-org brand_color in the orgs row:
sqlite3 ~/.safecadence/ui.sqlite "
  UPDATE orgs SET brand_color='#9333ea' WHERE id='org_customer_b';"
```

Last touched: 2026-05-25 — landed with v15.0 plugin loader + rule packs.
