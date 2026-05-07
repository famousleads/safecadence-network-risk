"""
v7.9 — Daily-use intelligence features that turn SafeCadence from a
toolkit into a habit.

Six modules:

  watchlists   pin specific assets/NHIs/principals/findings; alert on change
  comments     team-workflow comments + assignments on any entity
  timeline     chronological view of what changed (audit + daemon snapshots)
  automation   IF/THEN rules that fire on findings (auto-fix, notify, assign)
  briefing     personalized morning digest (overnight changes, top actions)
  ai_assistant natural-language Q&A over the fleet (BYO-AI)

Every module is JSON-file backed by default (~/.safecadence/intel/*.json),
so the v7.9 features work on a fresh install with no DB setup. The
daemon picks them up automatically — no separate process needed.
"""

from safecadence.intel.watchlists import (
    Watch, add_watch, list_watches, remove_watch, watch_changes,
)
from safecadence.intel.comments import (
    Comment, add_comment, list_comments, assign, list_assignments,
)
from safecadence.intel.timeline import (
    TimelineEvent, build_timeline,
)
from safecadence.intel.automation import (
    AutomationRule, evaluate_rules, list_rules, save_rule, delete_rule,
)
from safecadence.intel.briefing import build_briefing
from safecadence.intel.ai_assistant import ask_assistant

__all__ = [
    "Watch", "add_watch", "list_watches", "remove_watch", "watch_changes",
    "Comment", "add_comment", "list_comments", "assign", "list_assignments",
    "TimelineEvent", "build_timeline",
    "AutomationRule", "evaluate_rules", "list_rules", "save_rule", "delete_rule",
    "build_briefing",
    "ask_assistant",
]
