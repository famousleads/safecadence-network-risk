"""
v6.0 — Identity Intelligence adapters (5 read-only).

  - cisco_ise        Cisco ISE — ERS REST API + Open API
  - hpe_clearpass    HPE Aruba ClearPass — REST API
  - active_directory Microsoft AD via LDAP/LDAPS
  - entra_id         Microsoft Entra ID (Azure AD) — Microsoft Graph
  - okta             Okta — REST API

All adapters follow the existing BaseAdapter pattern and emit a UnifiedAsset
where the new `identity_block: Identity` is populated. Cross-platform —
pure Python, all HTTP via the existing ConnectionManager (httpx), all
LDAP via the optional `ldap3` package gated lazily.
"""

from __future__ import annotations

from typing import Any

from safecadence.platform.adapter_base import (
    AdapterCapabilities, BaseAdapter, ConnectionType, register_adapter,
)
from safecadence.platform.connection_manager import ConnectionManager
from safecadence.platform.health_scoring import score_asset_health
from safecadence.platform.schema import (
    AssetIdentity, Identity, UnifiedAsset,
)
from safecadence.identity.write_back import IdentityWriteBackMixin


def _id_asset(asset_id: str, vendor: str, family: str, raw: dict) -> UnifiedAsset:
    return UnifiedAsset(
        identity=AssetIdentity(asset_id=asset_id, vendor=vendor,
                                product_family=family, asset_type="identity"),
        raw_collection=raw,
    )


def _probe_groups(adapter) -> dict:
    """v9.51 — best-effort probe used inside test_connection().

    Returns ``{"count": N, "ok": True}`` when ``list_groups()``
    returns something (zero or more), or ``{"count": 0, "ok": False,
    "reason": "..."}`` when the call raises or the adapter's
    list_groups isn't implemented. Never raises — the parent
    test_connection already returns a status dict, this is just
    extra detail.
    """
    fn = getattr(adapter, "list_groups", None)
    if not callable(fn):
        return {"count": 0, "ok": False,
                "reason": "list_groups not implemented"}
    try:
        rows = fn() or []
        return {"count": len(rows), "ok": True}
    except Exception as exc:                            # pragma: no cover
        return {"count": 0, "ok": False,
                "reason": f"{type(exc).__name__}: {exc}"}


# ============================================================================
# Cisco ISE — ERS REST API
# ============================================================================

@register_adapter("cisco_ise")
class CiscoISEAdapter(IdentityWriteBackMixin, BaseAdapter):
    """Cisco Identity Services Engine via the ERS REST API.

    v6.0: pulls endpoints, identity groups, sessions, authz rules.
    v7.6: write-back via apply_policy() — POSTs ERS authz rules.
    """
    target_name = "ise"
    capabilities = AdapterCapabilities(
        name="cisco_ise", description="Cisco ISE (NAC + identity) via ERS REST",
        vendor="cisco", asset_types=["identity"],
        connection_types=[ConnectionType.REST],
        required_credentials=["username", "password"],
        documentation_url="https://developer.cisco.com/docs/identity-services-engine/",
        supports_write=True,
        write_capabilities=["authz_rule"],
    )

    def __init__(self, target, credentials, **kwargs):
        super().__init__(target, credentials, **kwargs)
        self.cm = ConnectionManager(verify_ssl=self.verify_ssl, timeout=self.timeout)
        # ERS API listens on 9060 by default
        self.base = (target if target.startswith("http")
                     else f"https://{target}:9060/ers")

    def _auth(self):
        return (self.credentials.get("username"), self.credentials.get("password"))

    def test_connection(self):
        r = self.cm.http_get(
            f"{self.base}/config/endpoint?size=1", auth=self._auth(),
            headers={"Accept": "application/json"},
        )
        return {"ok": r.get("ok"), "error": r.get("error"),
                "groups_probe": _probe_groups(self)}

    def collect(self, asset_id):
        h = {"Accept": "application/json"}
        out: dict[str, Any] = {}
        for key, path in [
            ("endpoints",       "config/endpoint"),
            ("identity_groups", "config/identitygroup"),
            ("authz_rules",     "config/authorizationprofile"),
            ("network_devices", "config/networkdevice"),
        ]:
            r = self.cm.http_get(f"{self.base}/{path}", auth=self._auth(), headers=h)
            out[key] = r.get("json") if r.get("ok") else {}
        return out

    def normalize(self, asset_id, raw):
        a = _id_asset(asset_id, "cisco", "ise", raw)
        eps = (raw.get("endpoints") or {}).get("SearchResult", {}).get("total", 0)
        groups = (raw.get("identity_groups") or {}).get("SearchResult", {}).get("total", 0)
        a.identity_block = Identity(
            provider="cisco-ise", tenant_id=self.target,
            user_count=int(eps or 0), group_count=int(groups or 0),
            nac_enrollment_status="profiled" if eps else "unknown",
        )
        a.health = score_asset_health(a)
        return a

    def list_groups(self) -> list[dict]:
        """v9.50 — Phase B: enumerate ISE identity groups.

        ISE's ERS API exposes identity groups by name + description but
        does NOT expose membership in a single endpoint — each user
        record carries a group reference, so reconstructing membership
        means iterating every InternalUser. That's expensive and rarely
        what the approver-group cache needs (ISE groups tend to be
        device classes, not human approver groups).

        For now we return the group list with empty ``members``. The
        consumer in ``identity/groups.py`` already degrades gracefully
        when ``members`` is empty — the group still appears in the
        cache and on /groups, but ``@group:NAME`` invitee expansion
        resolves to nothing for it. Operators using ISE for human
        approvers should set up the group in AD or Okta instead.
        """
        if not (self.credentials.get("username")
                  and self.credentials.get("password")):
            return []
        out: list[dict] = []
        try:
            r = self.cm.http_get(
                f"{self.base}/config/identitygroup",
                auth=self._auth(),
                headers={"Accept": "application/json"},
            )
            if not r.get("ok"):
                return []
            payload = r.get("json") or {}
            resources = ((payload.get("SearchResult") or {})
                          .get("resources") or [])
            for g in resources:
                if not isinstance(g, dict):
                    continue
                gid = g.get("id") or g.get("name") or ""
                gname = g.get("name") or gid
                out.append({"id": str(gid), "name": str(gname),
                              "members": []})
        except Exception:                                   # pragma: no cover
            return out
        return out

    # ---------------------------------------------------------------- v7.6
    def _commit(self, op, *, http_post, http_put, http_patch, ldap_modify) -> dict:
        url = f"{self.base}/config/authorization"
        body = op.payload["ers_body"]
        headers = {"Accept": "application/json",
                    "Content-Type": "application/json"}
        r = http_post(url, headers, body)
        committed: list[str] = []
        if isinstance(r, dict):
            # ISE returns id under SearchResult or directly under id; tolerate both
            for key in ("id", "rule_id"):
                if key in r:
                    committed.append(str(r[key]))
                    break
            if not committed and "AuthorizationRule" in r:
                rid = r["AuthorizationRule"].get("id")
                if rid:
                    committed.append(str(rid))
        if not committed:
            return {"error": f"ISE did not return rule id: {r!r}"}
        return {"committed_ids": committed}

    def _real_post(self, url: str, headers: dict, body):
        # ISE uses basic auth on every request
        return self.cm.http_post(url, json=body, headers=headers,
                                  auth=self._auth()).get("json")

    def _real_delete(self, url: str, headers: dict):
        try:
            import httpx  # type: ignore
        except ImportError as exc:                              # pragma: no cover
            raise RuntimeError("ISE rollback requires httpx") from exc
        r = httpx.delete(url, headers=headers, auth=self._auth(),
                          timeout=self.timeout, verify=self.verify_ssl)
        if r.status_code >= 400 and r.status_code != 404:
            raise RuntimeError(
                f"ISE DELETE {url} returned {r.status_code}: {r.text[:300]}")
        return {"status_code": r.status_code}

    # v9.33 #3 — committed_ids are ISE Authorization rule IDs from
    # POST /config/authorization. DELETE them to undo. 404 is treated
    # as "already gone" so a partial rollback can still complete.
    def _rollback(self, committed_ids, *, http_delete=None):
        delete_fn = http_delete or self._real_delete
        rolled: list[str] = []
        errors: list[str] = []
        for rid in committed_ids or []:
            try:
                delete_fn(f"{self.base}/config/authorization/{rid}",
                            {"Accept": "application/json"})
                rolled.append(str(rid))
            except Exception as exc:                            # pragma: no cover
                errors.append(f"{rid}: {exc}")
        return {"ok": not errors, "target": "ise",
                "rolled_back_ids": rolled, "errors": errors}


# ============================================================================
# HPE Aruba ClearPass — REST API
# ============================================================================

@register_adapter("hpe_clearpass")
class HPEClearPassAdapter(IdentityWriteBackMixin, BaseAdapter):
    """HPE Aruba ClearPass Policy Manager via REST API.

    OAuth2 client_credentials. v7.6 adds enforcement-profile + policy
    write-back via apply_policy().
    """
    target_name = "clearpass"
    capabilities = AdapterCapabilities(
        name="hpe_clearpass", description="HPE Aruba ClearPass via REST API",
        vendor="hpe", asset_types=["identity"],
        connection_types=[ConnectionType.REST],
        required_credentials=["client_id", "client_secret"],
        documentation_url="https://www.arubanetworks.com/techdocs/ClearPass/",
        supports_write=True,
        write_capabilities=["enforcement_profile", "enforcement_policy"],
    )

    def __init__(self, target, credentials, **kwargs):
        super().__init__(target, credentials, **kwargs)
        self.cm = ConnectionManager(verify_ssl=self.verify_ssl, timeout=self.timeout)
        self.base = (target if target.startswith("http")
                     else f"https://{target}/api")

    def test_connection(self):
        r = self.cm.http_post(f"{self.base}/oauth", json={
            "grant_type": "client_credentials",
            "client_id": self.credentials.get("client_id"),
            "client_secret": self.credentials.get("client_secret"),
        })
        return {"ok": r.get("ok"), "error": r.get("error"),
                "groups_probe": _probe_groups(self)}

    def collect(self, asset_id):
        out: dict[str, Any] = {}
        for key, path in [("endpoint", "endpoint"),
                          ("local-user", "local-user"),
                          ("network-device", "network-device"),
                          ("enforcement-profile", "config/enforcement-profile")]:
            r = self.cm.http_get(f"{self.base}/{path}")
            out[key] = r.get("json") if r.get("ok") else {}
        return out

    def normalize(self, asset_id, raw):
        a = _id_asset(asset_id, "hpe", "clearpass", raw)
        ep_count = (raw.get("endpoint") or {}).get("count", 0)
        u_count = (raw.get("local-user") or {}).get("count", 0)
        a.identity_block = Identity(
            provider="clearpass", tenant_id=self.target,
            user_count=int(u_count or 0) + int(ep_count or 0),
            group_count=0,
            nac_enrollment_status="profiled" if ep_count else "unknown",
        )
        a.health = score_asset_health(a)
        return a

    def list_groups(self) -> list[dict]:
        """v9.50 — Phase B: enumerate ClearPass local-user groups.

        Like ISE, ClearPass groups are typically used for device
        classes / role mappings rather than approver lists. The
        ``/api/local-user-group`` endpoint exposes the group list;
        membership requires per-user scans (each ``local-user``
        carries a ``role_name`` reference). Membership left empty
        for the same reason as ISE — the consumer in
        ``identity/groups.py`` degrades gracefully.
        """
        if not (self.credentials.get("client_id")
                  and self.credentials.get("client_secret")):
            return []
        out: list[dict] = []
        try:
            r = self.cm.http_get(f"{self.base}/local-user-group")
            if not r.get("ok"):
                return []
            payload = r.get("json") or {}
            items = (payload.get("_embedded") or {}).get("items") or []
            for g in items:
                if not isinstance(g, dict):
                    continue
                gid = g.get("id") or g.get("name") or ""
                gname = g.get("name") or gid
                out.append({"id": str(gid), "name": str(gname),
                              "members": []})
        except Exception:                                   # pragma: no cover
            return out
        return out

    # ---------------------------------------------------------------- v7.6
    def _commit(self, op, *, http_post, http_put, http_patch, ldap_modify) -> dict:
        committed: list[str] = []
        warnings: list[str] = []
        headers = {"Accept": "application/json",
                    "Content-Type": "application/json"}

        prof_url = f"{self.base}/enforcement-profile"
        prof_resp = http_post(prof_url, headers, op.payload["profile_body"])
        prof_id = (prof_resp or {}).get("id") if isinstance(prof_resp, dict) else None
        if prof_id is None:
            return {"error": f"ClearPass profile create failed: {prof_resp!r}"}
        committed.append(f"profile:{prof_id}")

        pol_url = f"{self.base}/enforcement-policy"
        pol_resp = http_post(pol_url, headers, op.payload["policy_body"])
        pol_id = (pol_resp or {}).get("id") if isinstance(pol_resp, dict) else None
        if pol_id is None:
            warnings.append(f"profile created but policy failed: {pol_resp!r}")
        else:
            committed.append(f"policy:{pol_id}")

        return {"committed_ids": committed, "warnings": warnings}

    def _real_post(self, url: str, headers: dict, body):
        return self.cm.http_post(url, json=body, headers=headers).get("json")

    def _real_delete(self, url: str, headers: dict):
        try:
            import httpx  # type: ignore
        except ImportError as exc:                              # pragma: no cover
            raise RuntimeError("ClearPass rollback requires httpx") from exc
        r = httpx.delete(url, headers=headers, timeout=self.timeout,
                          verify=self.verify_ssl)
        if r.status_code >= 400 and r.status_code != 404:
            raise RuntimeError(
                f"ClearPass DELETE {url} returned {r.status_code}: {r.text[:300]}")
        return {"status_code": r.status_code}

    # v9.33 #3 — committed_ids are tagged "profile:<id>" or
    # "policy:<id>" (the _commit format). Delete each in reverse so
    # we drop the policy before the profile it depends on. 404 is
    # treated as "already gone" so partial rollback still completes.
    def _rollback(self, committed_ids, *, http_delete=None):
        delete_fn = http_delete or self._real_delete
        rolled: list[str] = []
        errors: list[str] = []
        for tagged in reversed(list(committed_ids or [])):
            kind, _, raw_id = tagged.partition(":")
            if not raw_id:
                errors.append(f"unrecognized id format: {tagged!r}")
                continue
            path = ("enforcement-policy" if kind == "policy"
                    else "enforcement-profile")
            try:
                delete_fn(f"{self.base}/{path}/{raw_id}",
                            {"Accept": "application/json"})
                rolled.append(tagged)
            except Exception as exc:                            # pragma: no cover
                errors.append(f"{tagged}: {exc}")
        return {"ok": not errors, "target": "clearpass",
                "rolled_back_ids": rolled, "errors": errors}


# ============================================================================
# Active Directory via LDAP
# ============================================================================

@register_adapter("active_directory")
class ActiveDirectoryAdapter(IdentityWriteBackMixin, BaseAdapter):
    """Microsoft Active Directory via LDAP / LDAPS.

    v6.0: read-only. v7.6: write-back via apply_policy() — adds/removes
    group memberships using ldap3 modify operations. Lazy-imports ldap3
    so installations without it don't break.
    """
    target_name = "ad"
    capabilities = AdapterCapabilities(
        name="active_directory",
        description="Microsoft AD via LDAP/LDAPS",
        vendor="microsoft", asset_types=["identity"],
        connection_types=[ConnectionType.VENDOR_SDK],
        required_credentials=["bind_dn", "bind_password", "base_dn"],
        documentation_url="https://ldap3.readthedocs.io/",
        supports_write=True,
        write_capabilities=["group_membership"],
    )

    def __init__(self, target, credentials, **kwargs):
        super().__init__(target, credentials, **kwargs)
        self._ldap3 = None
        try:
            import ldap3
            self._ldap3 = ldap3
        except ImportError:
            pass

    def _conn(self):
        if not self._ldap3:
            raise RuntimeError("ldap3 not installed (pip install ldap3)")
        srv = self._ldap3.Server(self.target, use_ssl=self.target.startswith("ldaps"),
                                  get_info=self._ldap3.NONE)
        return self._ldap3.Connection(
            srv, user=self.credentials.get("bind_dn"),
            password=self.credentials.get("bind_password"),
            auto_bind=True,
        )

    def test_connection(self):
        if not self._ldap3:
            return {"ok": False, "error": "ldap3 not installed"}
        try:
            c = self._conn(); c.unbind()
            return {"ok": True, "groups_probe": _probe_groups(self)}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def collect(self, asset_id):
        if not self._ldap3:
            return {"error": "ldap3 not installed"}
        try:
            c = self._conn()
            base = self.credentials.get("base_dn", "")
            counts = {}
            for label, fltr in [
                ("user_count",  "(objectClass=user)"),
                ("group_count", "(objectClass=group)"),
                ("admin_users", "(memberOf=CN=Domain Admins,CN=Users," + base + ")"),
            ]:
                c.search(base, fltr, attributes=[],
                         search_scope=self._ldap3.SUBTREE,
                         paged_size=1, time_limit=10)
                # entries returned are paginated; total cookie unreliable across servers
                counts[label] = len(c.response or [])
            c.unbind()
            return counts
        except Exception as e:
            return {"error": str(e)}

    def normalize(self, asset_id, raw):
        a = _id_asset(asset_id, "microsoft", "active-directory", raw)
        a.identity_block = Identity(
            provider="ad",
            tenant_id=self.credentials.get("base_dn", "") or self.target,
            user_count=int(raw.get("user_count", 0) or 0),
            group_count=int(raw.get("group_count", 0) or 0),
            privileged_user_count=int(raw.get("admin_users", 0) or 0),
        )
        a.health = score_asset_health(a)
        return a

    def list_groups(self) -> list[dict]:
        """v9.50 — Phase B: enumerate AD groups + members via LDAP.

        Members are returned as ``sAMAccountName`` (the value Windows
        login flows use) when resolvable; falls back to the bare CN
        otherwise. Empty list if ldap3 isn't installed or the bind
        fails.
        """
        if not self._ldap3:
            return []
        out: list[dict] = []
        try:
            c = self._conn()
            base = self.credentials.get("base_dn", "")
            c.search(base, "(objectClass=group)",
                       attributes=["cn", "distinguishedName", "member",
                                     "sAMAccountName"],
                       search_scope=self._ldap3.SUBTREE,
                       paged_size=200, time_limit=10)
            for entry in (c.response or []):
                if not isinstance(entry, dict):
                    continue
                attrs = entry.get("attributes") or {}
                gname = (attrs.get("cn") or attrs.get("sAMAccountName")
                          or entry.get("dn") or "")
                if isinstance(gname, list):
                    gname = gname[0] if gname else ""
                gid = entry.get("dn") or gname
                member_dns = attrs.get("member") or []
                if isinstance(member_dns, str):
                    member_dns = [member_dns]
                # Resolve each member DN → sAMAccountName. Cap to 200
                # per group so a 5000-member nested group doesn't stall
                # the daemon refresh.
                members: list[str] = []
                for dn in member_dns[:200]:
                    try:
                        c.search(dn, "(objectClass=*)",
                                   attributes=["sAMAccountName"],
                                   search_scope=self._ldap3.BASE,
                                   time_limit=5)
                        for r in (c.response or []):
                            sam = (r.get("attributes") or {}).get(
                                "sAMAccountName")
                            if isinstance(sam, list):
                                sam = sam[0] if sam else ""
                            if sam:
                                members.append(str(sam))
                                break
                        else:
                            # Fall back to extracting CN from the DN
                            cn = dn.split(",", 1)[0]
                            if cn.lower().startswith("cn="):
                                members.append(cn[3:])
                    except Exception:                       # pragma: no cover
                        continue
                out.append({"id": str(gid), "name": str(gname),
                              "members": members})
            c.unbind()
        except Exception:                                   # pragma: no cover
            return out
        return out

    # ---------------------------------------------------------------- v7.6
    def _commit(self, op, *, http_post, http_put, http_patch, ldap_modify) -> dict:
        action = op.payload.get("action_kind", "advise")
        if action == "advise":
            return {"warnings": [op.summary]}

        target_group = op.payload.get("target_group", "")
        source_groups = op.payload.get("source_groups", [])
        principals = op.payload.get("principals", [])

        committed: list[str] = []
        warnings: list[str] = []

        # For source_groups, we collect their members and apply changes
        # to each member. ldap_modify(dn, changes) is the seam.
        for group_dn in source_groups:
            for principal_dn in self._members_of(group_dn):
                changes = self._build_membership_change(
                    principal_dn, target_group, action)
                try:
                    ldap_modify(target_group, changes)
                    committed.append(f"{action}:{principal_dn}->{target_group}")
                except Exception as exc:                          # pragma: no cover
                    warnings.append(f"failed {principal_dn}: {exc}")

        # Explicit principals (DNs)
        for p in principals:
            changes = self._build_membership_change(p, target_group, action)
            try:
                ldap_modify(target_group, changes)
                committed.append(f"{action}:{p}->{target_group}")
            except Exception as exc:                              # pragma: no cover
                warnings.append(f"failed {p}: {exc}")

        if not committed and not warnings:
            warnings.append("no principals were modified — empty source groups")

        return {"committed_ids": committed, "warnings": warnings}

    def _members_of(self, group_dn: str) -> list[str]:
        """Resolve members of an AD group. Empty list if ldap3 unavailable."""
        if not self._ldap3:
            return []
        try:
            c = self._conn()
            c.search(group_dn, "(objectClass=*)",
                      attributes=["member"],
                      search_scope=self._ldap3.BASE)
            members: list[str] = []
            for e in (c.entries or []):
                vals = getattr(e, "member", None)
                if vals is not None:
                    members.extend([str(v) for v in vals.values])
            c.unbind()
            return members
        except Exception:
            return []

    def _build_membership_change(self, principal_dn: str,
                                  target_group: str, action: str):
        """Build an ldap3-shaped change dict.

        For 'quarantine' action we ADD the principal to the target group
        (and could also REMOVE from privileged groups; we keep the
        operation atomic in v7.6 — multiple ldap_modify calls).
        For 'grant' we ADD the principal to the target group.
        """
        if not self._ldap3:
            # Return a generic shape so tests can assert on it
            return {"member": [("MODIFY_ADD", [principal_dn])]}
        return {"member": [(self._ldap3.MODIFY_ADD, [principal_dn])]}

    def _real_ldap_modify(self, dn: str, changes: dict) -> None:
        if not self._ldap3:
            raise RuntimeError("ldap3 not installed")
        c = self._conn()
        try:
            ok = c.modify(dn, changes)
            if not ok:
                raise RuntimeError(f"ldap modify failed: {c.last_error}")
        finally:
            c.unbind()

    # v9.33 #3 — committed_ids are tagged "<action>:<principal_dn>->
    # <target_group>" (the _commit format). To roll back: emit a
    # MODIFY_DELETE for the same membership we previously MODIFY_ADD'd,
    # against the same target_group DN.
    def _rollback(self, committed_ids, *, ldap_modify=None):
        modify_fn = ldap_modify or self._real_ldap_modify
        rolled: list[str] = []
        errors: list[str] = []
        for tagged in committed_ids or []:
            try:
                _, _, rest = tagged.partition(":")
                principal_dn, _, target_group = rest.partition("->")
                if not (principal_dn and target_group):
                    errors.append(f"unrecognized id format: {tagged!r}")
                    continue
                if self._ldap3:
                    changes = {"member": [(self._ldap3.MODIFY_DELETE,
                                              [principal_dn])]}
                else:
                    changes = {"member": [("MODIFY_DELETE",
                                              [principal_dn])]}
                modify_fn(target_group, changes)
                rolled.append(tagged)
            except Exception as exc:                            # pragma: no cover
                errors.append(f"{tagged}: {exc}")
        return {"ok": not errors, "target": "ad",
                "rolled_back_ids": rolled, "errors": errors}


# ============================================================================
# Microsoft Entra ID (Azure AD) — Microsoft Graph
# ============================================================================

@register_adapter("entra_id")
class EntraIDAdapter(IdentityWriteBackMixin, BaseAdapter):
    """Microsoft Entra ID (Azure AD) via Microsoft Graph.

    v6.0: read-only. v7.6: write-back via apply_policy() — POSTs/PATCHes
    Conditional Access policies through the Graph API.

    Uses client-credentials OAuth (app registration). Pulls users,
    groups, conditional-access policies, sign-in risk events.
    """
    target_name = "entra"
    capabilities = AdapterCapabilities(
        name="entra_id", description="Microsoft Entra ID (Azure AD) via Graph",
        vendor="microsoft", asset_types=["identity"],
        connection_types=[ConnectionType.REST],
        required_credentials=["tenant_id", "client_id", "client_secret"],
        documentation_url="https://learn.microsoft.com/graph/api/overview",
        supports_write=True,
        write_capabilities=["ca_policy"],
    )

    def __init__(self, target, credentials, **kwargs):
        super().__init__(target, credentials, **kwargs)
        self.cm = ConnectionManager(verify_ssl=self.verify_ssl, timeout=self.timeout)
        self._token: str | None = None

    def _get_token(self) -> str | None:
        if self._token: return self._token
        tid = self.credentials.get("tenant_id")
        cid = self.credentials.get("client_id")
        sec = self.credentials.get("client_secret")
        if not (tid and cid and sec):
            return None
        url = f"https://login.microsoftonline.com/{tid}/oauth2/v2.0/token"
        # Note: form-urlencoded body — using json= sends JSON; Graph accepts both,
        # but we POST raw JSON dict for simplicity. If your tenant requires form,
        # extend ConnectionManager.http_post to accept data=.
        r = self.cm.http_post(url, json={
            "client_id": cid, "client_secret": sec,
            "grant_type": "client_credentials",
            "scope": "https://graph.microsoft.com/.default",
        })
        if r.get("ok"):
            j = r.get("json") or {}
            self._token = j.get("access_token")
        return self._token

    def test_connection(self):
        ok = bool(self._get_token())
        return {"ok": ok,
                "error": "" if ok else "auth failed",
                "groups_probe": _probe_groups(self)}

    def collect(self, asset_id):
        tok = self._get_token()
        if not tok:
            return {"error": "no token"}
        h = {"Authorization": f"Bearer {tok}"}
        out: dict[str, Any] = {}
        for key, path in [
            ("users",  "/users/$count"),
            ("groups", "/groups/$count"),
            ("conditional_access",
             "/identity/conditionalAccess/policies"),
        ]:
            r = self.cm.http_get(f"https://graph.microsoft.com/v1.0{path}",
                                  headers={**h, "ConsistencyLevel": "eventual"})
            out[key] = r.get("json") if r.get("ok") else r.get("text")
        return out

    def normalize(self, asset_id, raw):
        a = _id_asset(asset_id, "microsoft", "entra-id", raw)
        users = raw.get("users")
        groups = raw.get("groups")
        # /users/$count returns a bare integer as text; tolerate both forms
        try: u = int(users) if users is not None else 0
        except (ValueError, TypeError): u = 0
        try: g = int(groups) if groups is not None else 0
        except (ValueError, TypeError): g = 0
        ca_policies = (raw.get("conditional_access") or {}).get("value", [])
        mfa_required = any("mfa" in str(p).lower() for p in ca_policies)
        a.identity_block = Identity(
            provider="entra", tenant_id=self.credentials.get("tenant_id", ""),
            user_count=u, group_count=g,
            mfa_enrolled=mfa_required,
            mfa_methods=["conditional_access:mfa"] if mfa_required else [],
        )
        a.health = score_asset_health(a)
        return a

    # ---------------------------------------------------------------- v7.6
    def _commit(self, op, *, http_post, http_put, http_patch, ldap_modify) -> dict:
        tok = self._get_token()
        if not tok:
            return {"error": "Entra: no Graph token (check tenant/client/secret)"}
        url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
        headers = {"Authorization": f"Bearer {tok}",
                    "Content-Type": "application/json"}
        body = op.payload["ca_body"]
        r = http_post(url, headers, body)
        if isinstance(r, dict) and r.get("id"):
            return {"committed_ids": [r["id"]]}
        return {"error": f"Entra Graph did not return policy id: {r!r}"}

    def list_groups(self) -> list[dict]:
        """v9.50 — Phase B: enumerate Entra groups + members via Graph.

        Members are returned as the userPrincipalName (e.g.
        ``alice@acme.onmicrosoft.com``) so they match the value Entra
        emits in JWT ``preferred_username`` claims. Empty list on auth
        failure.
        """
        tok = self._get_token()
        if not tok:
            return []
        h = {"Authorization": f"Bearer {tok}"}
        out: list[dict] = []
        try:
            r = self.cm.http_get(
                "https://graph.microsoft.com/v1.0/groups?$top=200",
                headers=h,
            )
            if not r.get("ok"):
                return []
            for g in ((r.get("json") or {}).get("value") or []):
                if not isinstance(g, dict):
                    continue
                gid = g.get("id") or ""
                gname = g.get("displayName") or gid
                members: list[str] = []
                m = self.cm.http_get(
                    f"https://graph.microsoft.com/v1.0/groups/{gid}/members?$top=200",
                    headers=h,
                )
                if m.get("ok"):
                    for u in ((m.get("json") or {}).get("value") or []):
                        if not isinstance(u, dict):
                            continue
                        upn = (u.get("userPrincipalName")
                                 or u.get("mail") or u.get("id") or "")
                        if upn:
                            members.append(str(upn))
                out.append({"id": gid, "name": gname, "members": members})
        except Exception:                                   # pragma: no cover
            return out
        return out

    def _real_post(self, url: str, headers: dict, body):
        return self.cm.http_post(url, json=body, headers=headers).get("json")

    def _real_delete(self, url: str, headers: dict):
        try:
            import httpx  # type: ignore
        except ImportError as exc:                              # pragma: no cover
            raise RuntimeError("Entra rollback requires httpx") from exc
        r = httpx.delete(url, headers=headers, timeout=self.timeout,
                          verify=self.verify_ssl)
        if r.status_code >= 400 and r.status_code != 404:
            raise RuntimeError(
                f"Entra DELETE {url} returned {r.status_code}: {r.text[:300]}")
        return {"status_code": r.status_code}

    # v9.33 #3 — committed_ids are Conditional-Access policy IDs from
    # POST /identity/conditionalAccess/policies. DELETE them to undo.
    # 404 is treated as already-gone so partial rollback completes.
    def _rollback(self, committed_ids, *, http_delete=None):
        delete_fn = http_delete or self._real_delete
        tok = self._get_token()
        if not tok:
            return {"ok": False, "target": "entra",
                     "errors": ["no Graph token for rollback"]}
        headers = {"Authorization": f"Bearer {tok}"}
        rolled: list[str] = []
        errors: list[str] = []
        for pid in committed_ids or []:
            try:
                delete_fn(
                    "https://graph.microsoft.com/v1.0/identity/"
                    f"conditionalAccess/policies/{pid}",
                    headers,
                )
                rolled.append(str(pid))
            except Exception as exc:                            # pragma: no cover
                errors.append(f"{pid}: {exc}")
        return {"ok": not errors, "target": "entra",
                "rolled_back_ids": rolled, "errors": errors}


# ============================================================================
# Okta — REST API
# ============================================================================

@register_adapter("okta")
class OktaAdapter(IdentityWriteBackMixin, BaseAdapter):
    """Okta via REST API. Token is an Okta API token, NOT OAuth.

    v7.5: write-back via apply_policy(). Supports group-rule upsert and
    read-only dry-run. Real PUTs gated by the caller (Tier-3 approval).
    v7.6: refactored onto IdentityWriteBackMixin for consistent shape
    across all 5 identity adapters.
    """
    target_name = "okta"
    capabilities = AdapterCapabilities(
        name="okta", description="Okta organization via REST API",
        vendor="okta", asset_types=["identity"],
        connection_types=[ConnectionType.REST],
        required_credentials=["api_token"],
        documentation_url="https://developer.okta.com/docs/reference/",
        supports_write=True,
        write_capabilities=["group_rule", "group_membership"],
    )

    def __init__(self, target, credentials, **kwargs):
        super().__init__(target, credentials, **kwargs)
        self.cm = ConnectionManager(verify_ssl=self.verify_ssl, timeout=self.timeout)
        # target is the Okta org domain, e.g. "acme.okta.com"
        self.base = (target if target.startswith("http")
                     else f"https://{target}/api/v1")
        self.headers = {
            "Authorization": f"SSWS {credentials.get('api_token', '')}",
            "Accept": "application/json",
        }

    def test_connection(self):
        r = self.cm.http_get(f"{self.base}/users?limit=1", headers=self.headers)
        # v9.51 — also probe groups so the operator sees at connect
        # time whether the IdP-groups cache will populate.
        groups_probe = _probe_groups(self)
        return {"ok": r.get("ok"), "error": r.get("error"),
                "groups_probe": groups_probe}

    def collect(self, asset_id):
        out: dict[str, Any] = {}
        for key, path in [("users", "users?limit=200"),
                          ("groups", "groups?limit=200"),
                          ("policies", "policies?type=ACCESS_POLICY")]:
            r = self.cm.http_get(f"{self.base}/{path}", headers=self.headers)
            out[key] = r.get("json") if r.get("ok") else r.get("text")
        return out

    def normalize(self, asset_id, raw):
        a = _id_asset(asset_id, "okta", "org", raw)
        users = raw.get("users") or []
        groups = raw.get("groups") or []
        active = sum(1 for u in users
                     if isinstance(u, dict) and u.get("status") == "ACTIVE")
        admin = sum(1 for g in groups
                    if isinstance(g, dict) and "Admin" in (g.get("profile") or {}).get("name", ""))
        a.identity_block = Identity(
            provider="okta", tenant_id=self.target,
            user_count=len(users) if isinstance(users, list) else 0,
            group_count=len(groups) if isinstance(groups, list) else 0,
            privileged_user_count=admin,
        )
        a.health = score_asset_health(a)
        return a

    def list_groups(self) -> list[dict]:
        """v9.50 — Phase B: enumerate Okta groups with members.

        Returns ``[{"id", "name", "members": [login,...]}, ...]`` for the
        IdP-sourced approver-group cache. Empty list on missing
        credentials or any HTTP failure — never raises so the daemon
        refresh never aborts.
        """
        if not (self.headers.get("Authorization") or "").endswith(""):
            pass  # always present; placeholder for future check
        if "SSWS " not in self.headers.get("Authorization", "") or \
                self.headers["Authorization"] == "SSWS ":
            return []
        out: list[dict] = []
        try:
            r = self.cm.http_get(f"{self.base}/groups?limit=200",
                                   headers=self.headers)
            if not r.get("ok"):
                return []
            for g in (r.get("json") or []):
                if not isinstance(g, dict):
                    continue
                gid = g.get("id") or ""
                profile = g.get("profile") or {}
                gname = profile.get("name") or gid
                members: list[str] = []
                # /groups/{id}/users — capped to keep the daemon quick
                m = self.cm.http_get(
                    f"{self.base}/groups/{gid}/users?limit=200",
                    headers=self.headers,
                )
                if m.get("ok"):
                    for u in (m.get("json") or []):
                        if not isinstance(u, dict):
                            continue
                        login = ((u.get("profile") or {}).get("login")
                                  or u.get("id") or "")
                        if login:
                            members.append(str(login))
                out.append({"id": gid, "name": gname, "members": members})
        except Exception:                                   # pragma: no cover
            return out
        return out

    # ---------------------------------------------------------------- v7.6
    # apply_policy is provided by IdentityWriteBackMixin. This adapter
    # only implements _commit + the real http seams.

    def _commit(self, op, *, http_post, http_put, http_patch, ldap_modify) -> dict:
        rule_payload = {
            "type": "group_rule",
            "name": op.payload["rule_name"],
            "conditions": {
                "expression": {"value": op.payload["expression"],
                                "type": "urn:okta:expression:1.0"},
            },
            "actions": {
                "assignUserToGroups": {
                    "groupIds": [op.payload["target_group"]],
                },
            },
        }
        committed: list[str] = []
        warnings: list[str] = []

        r = http_post(f"{self.base}/groups/rules", self.headers, rule_payload)
        if isinstance(r, dict) and r.get("id"):
            committed.append(r["id"])
            # activate (Okta returns rules INACTIVE by default)
            try:
                http_put(f"{self.base}/groups/rules/{r['id']}/lifecycle/activate",
                          self.headers, None)
            except Exception as exc:                            # pragma: no cover
                warnings.append(f"created but not activated: {exc}")
        else:
            return {"error": f"okta did not return rule id: {r!r}"}

        return {"committed_ids": committed, "warnings": warnings}

    def _real_post(self, url: str, headers: dict, body):
        return self.cm.http_post(url, json=body, headers=headers).get("json")

    def _real_put(self, url: str, headers: dict, body):
        try:
            import httpx  # type: ignore
        except ImportError as exc:
            raise RuntimeError(
                "Okta write-back requires httpx. "
                "Install with: pip install 'safecadence-netrisk[server]'"
            ) from exc
        h = {"Content-Type": "application/json", **(headers or {})}
        r = httpx.put(url, headers=h, json=body, timeout=self.timeout,
                       verify=self.verify_ssl)
        if r.status_code >= 400:
            raise RuntimeError(f"Okta PUT {url} returned {r.status_code}: {r.text[:300]}")
        try:
            return r.json()
        except ValueError:
            return {"status_code": r.status_code}

    def _real_delete(self, url: str, headers: dict):
        try:
            import httpx  # type: ignore
        except ImportError as exc:                              # pragma: no cover
            raise RuntimeError("Okta rollback requires httpx") from exc
        r = httpx.delete(url, headers=headers, timeout=self.timeout,
                          verify=self.verify_ssl)
        if r.status_code >= 400 and r.status_code != 404:
            raise RuntimeError(
                f"Okta DELETE {url} returned {r.status_code}: {r.text[:300]}")
        return {"status_code": r.status_code}

    # v9.33 #3 — undo a committed group rule. The committed_ids the
    # mixin captured are Okta rule IDs (from POST /groups/rules). To
    # roll back we DELETE each one. 404 is treated as "already gone"
    # so a partial rollback can still complete.
    def _rollback(self, committed_ids, *, http_delete=None):
        delete_fn = http_delete or self._real_delete
        rolled: list[str] = []
        errors: list[str] = []
        for rid in committed_ids or []:
            try:
                delete_fn(f"{self.base}/groups/rules/{rid}", self.headers)
                rolled.append(str(rid))
            except Exception as exc:                            # pragma: no cover
                errors.append(f"{rid}: {exc}")
        return {"ok": not errors, "target": "okta",
                "rolled_back_ids": rolled, "errors": errors}
