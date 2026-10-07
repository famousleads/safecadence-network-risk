"""Bundle only owned modules; extracted source distributions rebuild offline."""
from pathlib import Path
import shutil

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

OWNED = (
    "ui/desat_pages.py", "platform/public_safety.py", "platform/evidence_health.py",
    "demo_sheriff.py", "evidencewatch.py", "demo_campus.py", "community.py",
    "watch_intel.py", "mass_notify.py", "situation.py", "safecheck.py",
    "custody.py", "rollcall.py", "watches.py",
)


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version, build_data):
        root = Path(self.root)
        source = root.parent / "src" / "safecadence"
        bundle = root / "package" / "safecadence"
        if source.is_dir():
            if bundle.exists():
                shutil.rmtree(bundle)
            for name in OWNED:
                target = bundle / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source / name, target)
        expected = set(OWNED)
        actual = {str(p.relative_to(bundle)).replace("\\", "/") for p in bundle.rglob("*") if p.is_file()}
        if actual != expected:
            raise RuntimeError("Public Safety bundle is incomplete or contains unowned files")
