"""
Git-backed policy sync — pull/push policies as YAML in a Git repo.

Cross-platform: shells out to `git` only (works on Windows, Linux, Mac
as long as git is in PATH). No subprocess shell=True, args are list-based,
all paths are pathlib.

Repo layout expected:

    policies/
      <policy_id>.yaml
      <other>.yaml

Sync flow:
  1. clone / fetch the repo into ~/.safecadence/git_policies/<repo_hash>/
  2. read every policies/*.yaml file
  3. import each into the local store (overwriting if newer)
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path
from typing import Optional

try:
    import yaml
except ImportError:                           # pragma: no cover
    yaml = None

from safecadence.policy.audit import log as audit_log
from safecadence.policy.store import save
from safecadence.policy.templates import _to_policy


def _cache_root() -> Path:
    p = Path.home() / ".safecadence" / "git_policies"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _repo_dir(repo_url: str) -> Path:
    h = hashlib.sha256(repo_url.encode("utf-8")).hexdigest()[:12]
    return _cache_root() / h


def _git(cmd: list[str], cwd: Optional[Path] = None) -> tuple[bool, str]:
    """Run git with safe args (no shell). Returns (ok, output)."""
    try:
        r = subprocess.run(["git", *cmd], cwd=str(cwd) if cwd else None,
                           capture_output=True, text=True, encoding="utf-8",
                           check=False, timeout=60)
        ok = r.returncode == 0
        return ok, (r.stdout + r.stderr)
    except FileNotFoundError:
        return False, "git not found on PATH"
    except subprocess.TimeoutExpired:
        return False, "git timed out"


def sync(repo_url: str, *, branch: str = "main",
         actor: str = "system") -> dict:
    """Clone or fetch repo_url, then import every policies/*.yaml file."""
    if not yaml:
        return {"ok": False, "error": "PyYAML required"}
    target = _repo_dir(repo_url)
    if (target / ".git").exists():
        ok, out = _git(["fetch", "origin"], cwd=target)
        if not ok:
            return {"ok": False, "stage": "fetch", "error": out}
        ok, out = _git(["reset", "--hard", f"origin/{branch}"], cwd=target)
        if not ok:
            return {"ok": False, "stage": "reset", "error": out}
    else:
        if target.exists():
            shutil.rmtree(target)
        ok, out = _git(["clone", "--branch", branch, "--depth", "1",
                        repo_url, str(target)])
        if not ok:
            return {"ok": False, "stage": "clone", "error": out}

    pol_dir = target / "policies"
    if not pol_dir.exists():
        return {"ok": False, "error": "repo has no policies/ directory"}

    imported: list[str] = []
    for f in sorted(pol_dir.glob("*.yaml")):
        try:
            d = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        except Exception:
            continue
        policy = _to_policy(d)
        policy.source = "git"
        save(policy, actor=actor)
        imported.append(policy.policy_id)

    audit_log("git_sync", actor=actor,
              detail={"repo": repo_url, "branch": branch, "imported": imported})
    return {"ok": True, "imported": imported, "count": len(imported)}
