# Demo droplet upgrade — v15.1.1

Per `~/Desktop/SecurityAlgo/CLAUDE.md`, the demo at `demo.safecadence.com`
runs out of `/srv/safecadence/apps/demo/.venv` on droplet `104.131.183.149`.
Right now it's serving an older NetRisk version (probably v10.2). The
public site advertises v12–v15 features, so the demo should match.

## SSH from your Mac

```bash
ssh root@104.131.183.149
```

## On the droplet — one block

```bash
set -euxo pipefail

# 1. Check current version + service health
/srv/safecadence/apps/demo/.venv/bin/safecadence --version
systemctl is-active safecadence-demo
systemctl is-active safecadence-demo-reset.timer

# 2. Upgrade in-place
/srv/safecadence/apps/demo/.venv/bin/pip install --upgrade \
  'safecadence-netrisk[server]==15.1.1'

# 3. Pin pydantic just below 2.13 (matches the CLAUDE.md note about
#    pydantic 2.13 breaking FastAPI OpenAPI gen)
/srv/safecadence/apps/demo/.venv/bin/pip install 'pydantic<2.13'

# 4. Restart the demo service
systemctl stop safecadence-demo
sleep 5
systemctl start safecadence-demo

# 5. Confirm it's listening on the expected port (8003 per CLAUDE.md)
ss -tlnp | grep 8003 || echo "WARNING: not listening on 8003 — Caddy will 502"

# 6. Verify new version is what's running
/srv/safecadence/apps/demo/.venv/bin/safecadence --version

# 7. Re-trigger the demo data seed so the new schema migrations run
systemctl start safecadence-demo-reset.service || true

# 8. Test the live endpoints
curl -s -o /dev/null -w "/home: %{http_code}\n" https://demo.safecadence.com/home
curl -s -o /dev/null -w "/risks: %{http_code}\n" https://demo.safecadence.com/risks
curl -s -o /dev/null -w "/reports: %{http_code}\n" https://demo.safecadence.com/reports
curl -s -o /dev/null -w "/cluster-status: %{http_code}\n" \
  https://demo.safecadence.com/cluster-status
curl -s -o /dev/null -w "/help/topics: %{http_code}\n" \
  https://demo.safecadence.com/help/topics
curl -s -o /dev/null -w "/ai-agents: %{http_code}\n" https://demo.safecadence.com/ai-agents
```

## If the port-bind check fails (the CLAUDE.md quirk)

The `safecadence ui` CLI walks the port range when its asked-for port
is in TIME_WAIT. If `ss -tlnp | grep 8003` doesn't show the listener,
restart with a longer pause:

```bash
systemctl stop safecadence-demo
sleep 15
systemctl start safecadence-demo
ss -tlnp | grep 8003
```

## If anything goes sideways, the rollback is one line

```bash
/srv/safecadence/apps/demo/.venv/bin/pip install --upgrade \
  'safecadence-netrisk[server]==10.2.0'
systemctl restart safecadence-demo
```

(Substitute whatever version was running before; check
`pip show safecadence-netrisk` in the venv before upgrading if you
want to know the exact prior version.)

## Things to spot-check after upgrade

1. Open https://demo.safecadence.com/home — Safe Score visible, no errors
2. Open https://demo.safecadence.com/reports — wizard loads
3. Open https://demo.safecadence.com/cluster-status — new v12.1 page renders
4. Open https://demo.safecadence.com/ai-agents — new v14.0 page renders
5. Open https://demo.safecadence.com/help/topics — new v13 directory loads
6. Check Caddy isn't returning 502 anywhere (per the CLAUDE.md port quirk)

If any of those 404, check that `safecadence-network-risk[server]` is
the right extras-set (we want server + reports + intelligence in this
install). If routes still 404 after a clean restart, the package
metadata is probably missing the extras — `pip install --upgrade
'safecadence-netrisk[server,reports,intelligence]==15.1.1'` covers it.

Last touched: 2026-05-25 — alongside the v15.1.1 release.
