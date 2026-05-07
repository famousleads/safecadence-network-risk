"""
v9.38 — Small pages audit fixes.

The audit found all 7 surfaces real. Two transparency / UX gaps
shipped:

  1. /automation preview now shows a clear "Preview only — no actions
     taken" banner before the JSON dump.
  2. /timeline kinds filter has a <datalist> so operators don't typo
     into empty results.
"""

from __future__ import annotations


def test_automation_preview_shows_dry_run_banner():
    """Before v9.38 the preview button dumped raw JSON without saying
    'dry-run'. Now the operator can't miss it."""
    from safecadence.ui import intel_ui
    src = intel_ui._AUTO_SCRIPT
    assert "Preview only" in src, (
        "automation preview must explicitly say it's a dry-run; "
        "operators can otherwise misread 'would_fire' as 'fired'"
    )
    # Sanity: the existing endpoint call is still there
    assert "/api/intel/automation/preview" in src


def test_timeline_kinds_input_has_datalist_suggestions():
    """The kinds field must offer the actual emitter names so a typo
    doesn't return an empty timeline."""
    from safecadence.ui import intel_ui
    body = intel_ui._TIMELINE_BODY
    assert 'list="timeline-kinds"' in body
    assert 'id="timeline-kinds"' in body
    # Every kind the timeline actually emits should be in the datalist
    for kind in ("audit", "jit", "comment",
                 "assignment", "watchlist", "automation"):
        assert f'value="{kind}"' in body, (
            f"timeline datalist missing kind: {kind}"
        )


def test_audit_doc_exists_for_v9_38():
    """The audit-then-fix pattern requires a doc per release. The
    link_audit test ensures pages don't 404; this test ensures the
    audit doc lands too."""
    import os
    p = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "docs", "v9.38-small-pages-audit.md",
    )
    assert os.path.isfile(p), (
        f"missing v9.38 audit doc at {p}"
    )
    text = open(p).read()
    # Cross-check the audit listed all 7 surfaces and the fix items
    for surface in ("/timeline", "/share", "/automation",
                    "/watchlists", "/briefing", "/settings", "/audit"):
        assert surface in text, f"audit doc missing {surface}"
