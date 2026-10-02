#!/usr/bin/env python3
"""Bouncer: check a Python package BEFORE an AI agent installs it.

Usage (from repo root):
    python skills/bouncer/scripts/check.py <package> [<package> ...] [--log] [--by coco]

Reads PyPI metadata only. Never installs or downloads package code.
Verdicts: ALLOW (exit 0) · WARN (exit 1) · BLOCK (exit 2). Prints one JSON object per package.
Standard library only, so the skill works in any agent environment.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
POPULAR_FILE = HERE.parent / "references" / "popular_packages.txt"
NEW_PACKAGE_DAYS = 30        # created more recently than this -> WARN
YOUNG_PACKAGE_DAYS = 90      # young AND only one release -> WARN
EXIT = {"ALLOW": 0, "WARN": 1, "BLOCK": 2}


def normalize(name: str) -> str:
    """PEP 503 name normalization."""
    return re.sub(r"[-_.]+", "-", name).lower().strip()


def edit_distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def popular_packages() -> list[str]:
    if not POPULAR_FILE.exists():
        return []
    return [normalize(l) for l in POPULAR_FILE.read_text().splitlines() if l.strip() and not l.startswith("#")]


def fetch_pypi(name: str) -> dict | None:
    url = f"https://pypi.org/pypi/{name}/json"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def first_upload(data: dict) -> datetime | None:
    times = [f["upload_time_iso_8601"] for files in data.get("releases", {}).values() for f in files
             if f.get("upload_time_iso_8601")]
    if not times:
        return None
    return min(datetime.fromisoformat(t.replace("Z", "+00:00")) for t in times)


def check(package: str) -> dict:
    name = normalize(package)
    reasons: list[str] = []
    verdict = "ALLOW"

    # Typo check runs even if the package exists: squatters register look-alikes.
    for pop in popular_packages():
        if name != pop and edit_distance(name, pop) <= (1 if len(pop) <= 5 else 2):
            reasons.append(f"name is one or two letters away from popular package '{pop}' (possible typosquat)")
            verdict = "WARN"
            break

    try:
        data = fetch_pypi(name)
    except Exception as e:  # network trouble: fail closed, never silently allow
        return {"package": package, "verdict": "WARN", "reasons": [f"could not reach PyPI ({e}); human review needed"] + reasons}

    if data is None:
        return {"package": package, "verdict": "BLOCK",
                "reasons": ["does not exist on PyPI: likely invented by the AI; an attacker could register this name"] + reasons}

    releases = [v for v, files in data.get("releases", {}).items() if files]
    created = first_upload(data)
    if created:
        age_days = (datetime.now(timezone.utc) - created).days
        if age_days < NEW_PACKAGE_DAYS:
            reasons.append(f"first published only {age_days} days ago")
            verdict = "WARN"
        elif age_days < YOUNG_PACKAGE_DAYS and len(releases) <= 1:
            reasons.append(f"young package ({age_days} days) with a single release")
            verdict = "WARN"
    else:
        reasons.append("no uploaded files in any release")
        verdict = "WARN"

    vulns = data.get("vulnerabilities") or []
    if vulns:
        ids = ", ".join(v.get("id", "?") for v in vulns[:3])
        reasons.append(f"latest version has known vulnerabilities: {ids}")
        verdict = "WARN"

    urls = data.get("info", {}).get("project_urls") or {}
    if not any("github.com" in (u or "") or "gitlab.com" in (u or "") for u in urls.values()):
        reasons.append("no linked source repository (cannot review maintainers)")

    if not reasons:
        reasons.append(f"established package ({len(releases)} releases)")
    return {"package": package, "verdict": verdict, "reasons": reasons}


def log_result(result: dict, requested_by: str) -> None:
    """Optional: write to LEAKHUNTER.RESULTS.BOUNCER_LOG via the shared helper."""
    sys.path.insert(0, str(HERE.parents[2]))  # repo root
    from leakhunter import db  # noqa: E402
    conn = db.connect(db.ADMIN)
    try:
        db.log_bouncer(conn, package=result["package"], verdict=result["verdict"],
                       reasons="; ".join(result["reasons"]), requested_by=requested_by)
    finally:
        conn.close()


def main() -> int:
    ap = argparse.ArgumentParser(description="Check packages before an AI agent installs them.")
    ap.add_argument("packages", nargs="+")
    ap.add_argument("--log", action="store_true", help="also write to RESULTS.BOUNCER_LOG")
    ap.add_argument("--by", default="human", help="who asked: coco | gemma | claude | human")
    args = ap.parse_args()
    worst = 0
    for pkg in args.packages:
        result = check(pkg)
        print(json.dumps(result))
        if args.log:
            try:
                log_result(result, args.by)
            except Exception as e:
                print(json.dumps({"package": pkg, "log_error": str(e)}), file=sys.stderr)
        worst = max(worst, EXIT[result["verdict"]])
    return worst


if __name__ == "__main__":
    sys.exit(main())
