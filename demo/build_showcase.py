#!/usr/bin/env python3
"""Build docs/showcase.html: the interactive LeakHunter dashboard, one self-contained file.

Reads LEAKHUNTER as LH_ADMIN (attack rounds, legit runs, Bouncer log, firewall audit trail, and the synthetic
patients for the re-identification slider), embeds it into docs/showcase_template.html and writes docs/showcase.html.
Nothing is fetched at view time except optional live PyPI lookups in the Bouncer tab. All data is synthetic.

Run from the repo root:  python demo/build_showcase.py     (open docs/showcase.html, no server needed)
"""
from __future__ import annotations

import json
import re
import sys
from datetime import date, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from leakhunter import db  # noqa: E402

TEMPLATE = ROOT / "docs" / "showcase_template.html"
OUT = ROOT / "docs" / "showcase.html"
_ACCOUNT = re.compile(r"\b[A-Z0-9]{5,}-[A-Z0-9]{5,}\b")


def clean(v):
    """JSON-safe, with anything that looks like a Snowflake account id removed."""
    if isinstance(v, (datetime, date)):
        return v.isoformat()
    if isinstance(v, str):
        return _ACCOUNT.sub("<account>", v)
    return v


def rows(conn, sql: str) -> list[dict]:
    cols, data = db.query(conn, sql)
    return [{c.lower(): clean(v) for c, v in zip(cols, r)} for r in data]


def case_of(sql: str, verdict: str) -> str | None:
    s = " ".join(sql.upper().split())
    if "GRANT ROLE" in s:
        return "role_grant"
    if "PACKAGES" in s:
        return "bad_package"
    if "PATIENT_ANALYTICS" in s:
        return "good_view" if verdict == "PASS" else "bad_view"
    return None


def main() -> None:
    conn = db.connect(db.ADMIN)
    try:
        score = rows(conn, "SELECT ROUND_NO, LEAKS, ATTACKS, LEGIT_PASSED, LEGIT_TOTAL "
                           "FROM LEAKHUNTER.RESULTS.SCOREBOARD ORDER BY ROUND_NO")
        latest = max((r["round_no"] for r in score), default=0)
        attacks = rows(conn, f"SELECT ATTACK_ID, GOAL, TECHNIQUE, SOURCE, TARGETS_LEAK, SUCCEEDED, ERROR, EVIDENCE "
                             f"FROM LEAKHUNTER.RESULTS.ATTACK_RUNS WHERE ROUND_NO = {latest} ORDER BY ATTACK_ID")
        legit = rows(conn, f"SELECT QUERY_ID, DESCRIPTION, PASSED FROM LEAKHUNTER.RESULTS.LEGIT_RUNS "
                           f"WHERE ROUND_NO = {latest} ORDER BY QUERY_ID")
        fixes = rows(conn, "SELECT ATTACK_ID, FIX_TYPE, SQL_APPLIED, APPLIED_BY FROM LEAKHUNTER.RESULTS.FIXES "
                           "ORDER BY APPLIED_AT")
        bouncer = rows(conn, "SELECT PACKAGE, VERDICT, REASONS, REQUESTED_BY, CHECKED_AT FROM "
                             "LEAKHUNTER.RESULTS.BOUNCER_LOG ORDER BY CHECKED_AT DESC LIMIT 200")
        try:
            audit_raw = rows(conn, "SELECT CHANGE_ID, PARENT_ID, SUBMITTED_BY, CHANGE_SQL, VERDICT, MERGED, "
                                   "ATTACKS_RUN, FINDINGS, PACKAGES, CREATED_AT FROM LEAKHUNTER.RESULTS.CHANGE_AUDIT "
                                   "ORDER BY CREATED_AT DESC LIMIT 100")
        except Exception:
            audit_raw = []
        patients = [[r["zip"], r["dob"], r["sex"]] for r in rows(
            conn, "SELECT ZIP, DOB, SEX FROM LEAKHUNTER.DATA.PATIENTS ORDER BY PATIENT_ID")]
        tables = rows(conn, "SELECT TABLE_SCHEMA || '.' || TABLE_NAME AS NAME, ROW_COUNT AS N FROM "
                            "LEAKHUNTER.INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA IN ('DATA','SCRATCH') "
                            "AND ROW_COUNT IS NOT NULL ORDER BY 1")
    finally:
        conn.close()

    # latest firewall run per demo case, with its real findings and attack transcript
    cases: dict[str, dict] = {}
    for r in audit_raw:
        case = case_of(r["change_sql"] or "", r["verdict"])
        if case and case not in cases:
            body = json.loads(r["findings"] or "{}")
            cases[case] = {"sql": r["change_sql"], "verdict": r["verdict"], "merged": r["merged"],
                           "attacks_run": r["attacks_run"], "packages": r["packages"], "when": r["created_at"],
                           "findings": [{k: clean(f.get(k, "")) for k in ("kind", "object", "detail", "evidence", "fix")}
                                        for f in body.get("findings", []) if f.get("blocking")],
                           "probes": [clean(s) for s in body.get("attack_path", []) if s.get("step") == "object_probe"],
                           "preexisting": body.get("preexisting_leaks", [])}
    # one row per package, newest verdict wins
    seen, pkgs = set(), []
    for b in bouncer:
        if b["package"] not in seen:
            seen.add(b["package"])
            pkgs.append(b)

    pop_file = ROOT / "skills" / "bouncer" / "references" / "popular_packages.txt"
    popular = [re.sub(r"[-_.]+", "-", ln).lower().strip() for ln in pop_file.read_text(encoding="utf-8").splitlines()
               if ln.strip() and not ln.startswith("#")]
    data = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "rounds": score, "latest_round": latest, "attacks": attacks, "legit": legit, "fixes": fixes,
        "bouncer": pkgs, "bouncer_total": len(bouncer), "firewall_cases": cases,
        "firewall_total": len(audit_raw),
        "firewall_blocked": sum(1 for r in audit_raw if r["verdict"] == "BLOCK"),
        "patients": patients, "tables": tables, "popular": popular,
    }
    html = TEMPLATE.read_text(encoding="utf-8").replace("/*__DATA__*/null", json.dumps(data, default=str))
    OUT.write_text(html, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} ({OUT.stat().st_size // 1024} KB): {len(attacks)} attacks, "
          f"{len(legit)} legit, {len(pkgs)} packages, {len(audit_raw)} firewall runs, {len(patients)} patients, "
          f"cases {sorted(cases)}")


if __name__ == "__main__":
    main()
