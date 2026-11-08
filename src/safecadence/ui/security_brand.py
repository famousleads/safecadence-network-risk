"""Locally bundled security branding and licensed Lucide icons."""
from functools import lru_cache
from importlib.resources import files


ICON_NAMES = (
    "activity", "archive-restore", "bell", "book-open", "bot", "boxes",
    "calendar-clock", "camera", "chart-no-axes-combined", "check",
    "chevron-down", "chevron-right", "clipboard-check", "clock", "database",
    "download", "file-check", "file-text", "flag", "git-branch", "globe",
    "house", "key-round", "layers", "layout-dashboard", "list-checks",
    "lock-keyhole", "mail", "map", "menu", "moon", "network", "radio",
    "scan-line", "search", "settings", "shield", "shield-alert", "shield-check",
    "sun", "tag", "terminal", "triangle-alert", "user-round", "users",
    "workflow", "wrench", "x", "zap",
)


@lru_cache(maxsize=len(ICON_NAMES))
def icon(name: str) -> str:
    if name not in ICON_NAMES:
        raise ValueError("Unknown UI icon")
    svg = files("safecadence.ui").joinpath("assets", "icons", name + ".svg").read_text()
    return svg.replace("<svg", '<svg aria-hidden="true" focusable="false"', 1)


@lru_cache(maxsize=1)
def brand_mark() -> str:
    return files("safecadence.ui").joinpath("assets", "security-mark.svg").read_text()


@lru_cache(maxsize=1)
def theme_css() -> str:
    return files("safecadence.ui").joinpath("security_theme.css").read_text()


def render_brand(html: str) -> str:
    html = html.replace("%SECURITY_THEME%", theme_css()).replace("%SECURITY_MARK%", brand_mark())
    for name in ICON_NAMES:
        token = "%ICON:" + name + "%"
        if token in html:
            html = html.replace(token, icon(name))
    return html
