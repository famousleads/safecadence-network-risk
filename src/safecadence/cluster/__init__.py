"""SafeCadence cluster / failover (v10.7).

Two modules:

* :mod:`safecadence.cluster.health` — local + peer health snapshots.
* :mod:`safecadence.cluster.failover` — Redis-leased active node election.

All env-gated. Missing Redis or peers = single-node "always active"
behaviour, identical to v10.6.
"""

from safecadence.cluster.health import node_health, cluster_state
from safecadence.cluster.failover import (
    am_i_active, renew_lease, try_take_lease, release_lease, start_lease_loop,
)

__all__ = [
    "node_health", "cluster_state",
    "am_i_active", "renew_lease", "try_take_lease", "release_lease",
    "start_lease_loop",
]
