"""Package Guard: vets every package a proposed change would pull into the warehouse.

Runs as step 0 of leakcheck, before any clone is made. Catches:
  - packages that are not on the approved list (firewall/packages.yaml)
  - typosquats (one or two letters away from an approved package, e.g. 'pandsa')
  - denied packages / stdlib modules that can move data out (socket, paramiko, ...)
  - IMPORTS = (...) from a stage (unreviewed code) and EXTERNAL_ACCESS_INTEGRATIONS (network egress)

Run:  python -m firewall.package_guard --sql-file change.sql
      python -m firewall.package_guard --requirements requirements.txt
Exit code 0 = PASS, 2 = BLOCK.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

POLICY_FILE = Path(__file__).with_name("packages.yaml")
_STDLIB = set(getattr(sys, "stdlib_module_names", ()))


def _norm(name: str) -> str:
    return re.split(r"[=<>!~\[; ]", name.strip().strip("'\""), maxsplit=1)[0].lower().replace("_", "-")


def load_policy() -> dict:
    with open(POLICY_FILE, encoding="utf-8") as f:
        p = yaml.safe_load(f) or {}
    return {"approved": {_norm(x) for x in p.get("approved", [])},
            "denied": {_norm(k): v for k, v in (p.get("denied") or {}).items()},
            "denied_modules": {k.lower(): v for k, v in (p.get("denied_modules") or {}).items()}}


def _distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def judge_package(name: str, policy: dict) -> dict:
    """status: ok | denied | typosquat | unapproved"""
    n = _norm(name)
    if n in policy["denied"]:
        return {"name": n, "status": "denied", "detail": policy["denied"][n]}
    if n in policy["approved"]:
        return {"name": n, "status": "ok", "detail": "approved"}
    for good in policy["approved"]:
        if len(n) >= 5 and _distance(n, good) <= 2:
            return {"name": n, "status": "typosquat", "detail": f"looks like the approved package '{good}'"}
    return {"name": n, "status": "unapproved", "detail": "not on the approved package list"}


def _quoted(text: str) -> list[str]:
    return [a or b for a, b in re.findall(r"'([^']*)'|\"([^\"]*)\"", text)]


def extract(sql: str) -> dict:
    """Pull package-like things out of change SQL."""
    packages, imports, egress, modules = [], [], [], []
    for m in re.finditer(r"\bPACKAGES\s*=\s*\(([^)]*)\)", sql, re.I):
        packages += _quoted(m.group(1))
    for m in re.finditer(r"\bIMPORTS\s*=\s*\(([^)]*)\)", sql, re.I):
        imports += _quoted(m.group(1))
    for m in re.finditer(r"\bEXTERNAL_ACCESS_INTEGRATIONS\s*=\s*\(([^)]*)\)", sql, re.I):
        egress.append(m.group(1).strip() or "(none named)")
    for m in re.finditer(r"pip\s+install\s+([^\s;'\"]+)", sql, re.I):
        packages.append(m.group(1))
    for body in re.findall(r"\$\$(.*?)\$\$", sql, re.S):  # inline Python UDF / procedure bodies
        for m in re.finditer(r"^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))", body, re.M):
            modules.append((m.group(1) or m.group(2)).split(".")[0])
    return {"packages": packages, "imports": imports, "egress": egress, "modules": modules}


def check_sql(sql: str, policy: dict | None = None) -> dict:
    policy = policy or load_policy()
    found = extract(sql)
    results = [judge_package(p, policy) for p in found["packages"]]
    for mod in found["modules"]:
        low = mod.lower()
        if low in policy["denied_modules"]:
            results.append({"name": mod, "status": "denied", "detail": policy["denied_modules"][low]})
        elif low not in _STDLIB:
            results.append(judge_package(mod, policy))
    for path in found["imports"]:
        results.append({"name": path, "status": "unreviewed",
                        "detail": "code imported from a stage was never reviewed"})
    for integ in found["egress"]:
        results.append({"name": f"EXTERNAL_ACCESS_INTEGRATIONS={integ}", "status": "egress",
                        "detail": "gives the code network access, so data could leave the warehouse"})
    bad = [r for r in results if r["status"] != "ok"]
    return {"verdict": "BLOCK" if bad else "PASS", "checked": results, "problems": bad}


def check_requirements(text: str, policy: dict | None = None) -> dict:
    policy = policy or load_policy()
    names = [ln.split("#")[0].strip() for ln in text.splitlines()]
    results = [judge_package(n, policy) for n in names if n]
    bad = [r for r in results if r["status"] != "ok"]
    return {"verdict": "BLOCK" if bad else "PASS", "checked": results, "problems": bad}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sql-file")
    ap.add_argument("--requirements")
    args = ap.parse_args()
    if args.sql_file:
        out = check_sql(Path(args.sql_file).read_text(encoding="utf-8"))
    elif args.requirements:
        out = check_requirements(Path(args.requirements).read_text(encoding="utf-8"))
    else:
        ap.error("give --sql-file or --requirements")
    print(json.dumps(out, indent=2))
    sys.exit(0 if out["verdict"] == "PASS" else 2)


if __name__ == "__main__":
    main()
