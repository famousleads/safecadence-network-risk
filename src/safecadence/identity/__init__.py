"""
v7.5 — Identity Intelligence engine.

Three modules cooperate:

* `ir`                   The unified policy IR. JSON-serializable, schema-validated.
* `effective_permissions`  Pure-Python ALLOW/DENY resolver that composes ISE +
                         AD + Entra + Okta declared rules from the existing
                         platform store.
* `ai_translator`        BYO-key NL → IR step. AI is constrained to producing
                         IR JSON; the per-system change preview is computed
                         deterministically downstream so the AI cannot
                         hallucinate changes that ship.

The Okta write-back path lives on `platform.adapters.identity_adapters.OktaAdapter`
to keep adapter logic next to the rest of the adapter code.
"""

from safecadence.identity.ir import (
    Condition, Decision, PrincipalSelector, ResourceSelector, Rule,
    UnifiedPolicyIR, validate_ir,
)
from safecadence.identity.write_back import ApplyResult, IdentityWriteBackMixin
from safecadence.identity.attack_paths import (
    IdentityEdge, IdentityPath, compute_identity_paths,
)
from safecadence.identity.jit import (
    JITGrant, expire_due, grant, grant_to_ir, list_grants, revoke,
)
from safecadence.identity.conflict_resolution import (
    ConflictPolicy, PrecedenceRule, load_policy, resolve_conflict,
)

__all__ = [
    "Condition", "Decision", "PrincipalSelector", "ResourceSelector",
    "Rule", "UnifiedPolicyIR", "validate_ir",
    "ApplyResult", "IdentityWriteBackMixin",
    "IdentityEdge", "IdentityPath", "compute_identity_paths",
    "JITGrant", "expire_due", "grant", "grant_to_ir", "list_grants", "revoke",
    "ConflictPolicy", "PrecedenceRule", "load_policy", "resolve_conflict",
]
