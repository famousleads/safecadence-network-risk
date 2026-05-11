"""
SafeCadence third-party integrations (v10.6+).

Modules:
  * ``slack``       — Slack OAuth 2.0 install + slash command + signature verify.
  * ``jira``        — Atlassian Jira 3LO OAuth + create issue + sync stub.
  * ``servicenow``  — ServiceNow Table API incident create (v10.7).
  * ``teams``       — Microsoft Teams webhook posting (v10.7).
  * ``splunk``      — Splunk HEC event forwarder (v10.7).

Each module is **env-gated**. Missing OAuth client credentials make the
public install endpoints return a clear "not configured" message instead
of crashing — keeps the demo open.
"""
