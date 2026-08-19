"""
safecadence.incidents — native incident objects (DESAT §7).

Event → correlate → INCIDENT → impact → notify → assign → investigate
→ resolve → close. Before this package, incidents lived only in
external tools (ServiceNow/Jira/PagerDuty); now NetRisk owns the
object and the externals become mirrors.
"""

from safecadence.incidents.store import (
    Incident, create_incident, get_incident, list_incidents,
    transition_incident, add_note, attach_events, attach_or_open_for_event,
    VALID_STATUSES,
)

__all__ = [
    "Incident", "create_incident", "get_incident", "list_incidents",
    "transition_incident", "add_note", "attach_events",
    "attach_or_open_for_event", "VALID_STATUSES",
]
