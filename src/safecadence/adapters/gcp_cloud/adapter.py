from __future__ import annotations

import re

from safecadence.core.adapter import BaseAdapter
from safecadence.core.registry import register_adapter
from safecadence.core.schema import ParsedConfig


_PROJ_RE = re.compile(r'projects/([\w-]+)|"project":\s*"([\w-]+)"')


@register_adapter
class GCPCloudAdapter(BaseAdapter):
    slug = "gcp-cloud"
    label = "Google Cloud project"
    os_family = ["gcp"]
    filename_hints = ("gcp", "gcloud", "google-cloud", "tf-gcp")
    content_hints = (
        "google_compute_firewall",
        "google_storage_bucket",
        "google_container_cluster",
        "googleapis.com",
        "projects/",
        "iam.gserviceaccount.com",
    )

    @classmethod
    def parse_config(cls, text: str) -> ParsedConfig:
        proj = ""
        if (m := _PROJ_RE.search(text or "")):
            proj = m.group(1) or m.group(2) or ""
        return ParsedConfig(
            vendor="gcp-cloud",
            device_type="cloud",
            hostname=proj or "gcp-project",
            os="gcp",
            version="",
            model="GCP",
            raw_config=text or "",
        )
