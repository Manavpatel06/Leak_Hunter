"""Audit report (owner: Manav). Reads LEAKHUNTER.RESULTS as LH_ADMIN, writes report/audit_report.md.

    python -m report.generate                    # -> report/audit_report.md
    python -m report.generate --out other.md

One page, plain English: every leak found, the rule it breaks, the fix applied, and whether the
re-check proved it closed. Ends with rounds run, leaks before/after, legit queries before/after.

Privacy: attack EVIDENCE (sample rows) is never copied into the report, only counts and names.
Regulation tags are indicative pointers for a reviewer, not legal advice.
"""
from __future__ import annotations

import argparse
import datetime as dt
from pathlib import Path

LEAK_TEXT = {
    "L1": "Patient SSNs were readable in clear text by the analyst role.",
    "L2": "Employee salaries could be read next to employee names.",
    "L3": "'Anonymized' patient data (ZIP + birth date + sex) could be linked to free public census "
          "data to single out real people.",
    "L4": "The analyst role inherited the HR role and could read private performance reviews.",
    "L5": "A forgotten raw export of the patient table sat in SCRATCH, readable by the analyst.",
    "L6": "A reporting view joined patient names to diagnoses.",
}
# fix-playbook.md "Regulation tags"
LEAK_TAGS = {
    "L1": ["HIPAA Privacy Rule (minimum necessary)"],
    "L2": ["GDPR Art. 5(1)(f) integrity and confidentiality", "state privacy law"],
    "L3": ["HIPAA de-identification standard (45 CFR 164.514)"],
    "L4": ["GDPR Art. 32 security of processing", "least privilege"],
    "L5": ["HIPAA Privacy Rule (minimum necessary)", "GDPR Art. 32 security of processing"],
    "L6": ["HIPAA Privacy Rule (minimum necessary)"],
}
ATTACK_TO_LEAK = {"A01": "L1", "A02": "L2", "A03": "L3", "A04": "L4", "A05": "L5", "A06": "L6"}


def _cell(v) -> str:
    """Safe for a markdown table cell."""
    return " ".join(str("" if v is None else v).split()).replace("|", "\\|")


def _tags(leak: str, technique: str, goal: str) -> list[str]:
    if leak in LEAK_TAGS:
        return LEAK_TAGS[leak]
    text = f"{technique} {goal}".lower()
    if "reident" in text or "identify" in text:
        return LEAK_TAGS["L3"]
    if "employee" in text or "salary" in text or "review" in text or "role" in text:
        return LEAK_TAGS["L2"] + ["least privilege"]
    return LEAK_TAGS["L1"]


def fetch() -> dict:
    from leakhunter import db

    conn = db.connect(db.ADMIN)
    try:
        def rows(sql):
            cols, rs = db.query(conn, sql)
            return [dict(zip(cols, r)) for r in rs]
        data = {
            "scoreboard": rows("SELECT ROUND_NO, LEAKS, ATTACKS, LEGIT_PASSED, LEGIT_TOTAL "
                               "FROM LEAKHUNTER.RESULTS.SCOREBOARD ORDER BY ROUND_NO"),
            "attacks": rows("SELECT ROUND_NO, ATTACK_ID, GOAL, TECHNIQUE, SOURCE, TARGETS_LEAK, SUCCEEDED "
                            "FROM LEAKHUNTER.RESULTS.ATTACK_RUNS ORDER BY ROUND_NO, ATTACK_ID"),
            "fixes": rows("SELECT ROUND_NO, ATTACK_ID, FIX_TYPE, SQL_APPLIED, RATIONALE, APPLIED_BY, APPLIED_AT "
                          "FROM LEAKHUNTER.RESULTS.FIXES ORDER BY APPLIED_AT"),
            "planted": rows("SELECT LEAK_ID FROM LEAKHUNTER.RESULTS.PLANTED ORDER BY LEAK_ID"),
            "bouncer": [],
        }
        try:  # optional: Reya's Bouncer log (sql/00_setup.sql section E)
            data["bouncer"] = rows("SELECT VERDICT, COUNT(*) AS N FROM LEAKHUNTER.RESULTS.BOUNCER_LOG GROUP BY 1")
        except Exception:
            pass
        return data
    finally:
        conn.close()


def build(data: dict, now: dt.datetime | None = None) -> str:
    now = now or dt.datetime.now()
    board = data["scoreboard"]
    attacks = data["attacks"]
    fixes = data["fixes"]
    out = ["# LeakHunter audit report", "",
           f"Generated {now:%Y-%m-%d %H:%M} · warehouse `LEAKHUNTER` · all data synthetic", ""]

    if not board or not attacks:
        out += ["No attack rounds have been run yet. Run `python -m referee.run_round` first.", ""]
        return "\n".join(out)

    rounds = [int(r["ROUND_NO"]) for r in board]
    last_round = max(rounds)
    # per attack: every round it ran in, and whether it succeeded there
    runs: dict[str, dict[int, bool]] = {}
    meta: dict[str, dict] = {}
    for a in attacks:
        aid = a["ATTACK_ID"]
        runs.setdefault(aid, {})[int(a["ROUND_NO"])] = runs.get(aid, {}).get(int(a["ROUND_NO"]), False) or bool(a["SUCCEEDED"])
        meta.setdefault(aid, a)
    fixes_by: dict[str, list[dict]] = {}
    for f in fixes:
        fixes_by.setdefault(f["ATTACK_ID"], []).append(f)

    found = [aid for aid in sorted(runs) if any(runs[aid].values())]
    first, last = board[0], board[-1]

    # ---- summary
    still_open = [aid for aid in found if runs[aid].get(max(runs[aid]), False)]
    verified = [aid for aid in found if aid not in still_open]
    out += ["## Summary", ""]
    out += [f"- **{len(found)}** attack(s) succeeded at least once across **{len(rounds)}** round(s); "
            f"**{len(verified)}** now proven closed, **{len(still_open)}** still open."]
    out += [f"- Leaks: **{first['LEAKS'] or 0}** in round {first['ROUND_NO']} → "
            f"**{last['LEAKS'] or 0}** in round {last['ROUND_NO']}."]
    out += [f"- Legitimate analyst queries: **{first['LEGIT_PASSED'] or 0}/{first['LEGIT_TOTAL'] or 0}** → "
            f"**{last['LEGIT_PASSED'] or 0}/{last['LEGIT_TOTAL'] or 0}** "
            f"({'no legitimate work broken' if (last['LEGIT_PASSED'] or 0) == (last['LEGIT_TOTAL'] or 0) else 'SOME LEGITIMATE QUERIES FAIL'})."]
    if data.get("planted"):
        out += [f"- Planted for this test: {', '.join(r['LEAK_ID'] for r in data['planted'])}."]
    out += [""]

    # ---- findings
    out += ["## Findings", "",
            "| Attack | What leaked | Rule it breaks | Fix applied | Re-check |",
            "|---|---|---|---|---|"]
    for aid in found:
        m = meta[aid]
        leak = (m.get("TARGETS_LEAK") or "").upper() or ATTACK_TO_LEAK.get(aid, "")
        what = LEAK_TEXT.get(leak) or (m.get("GOAL") or "Sensitive data reachable by the analyst role.")
        tags = "; ".join(_tags(leak, m.get("TECHNIQUE") or "", m.get("GOAL") or ""))
        fx = fixes_by.get(aid, [])
        if fx:
            f = fx[-1]
            first_sql = (f.get("SQL_APPLIED") or "").strip().splitlines()[0] if f.get("SQL_APPLIED") else ""
            fix = f"{f['FIX_TYPE']} by {f['APPLIED_BY']}: `{first_sql.rstrip(';')}`" if first_sql else f"{f['FIX_TYPE']} by {f['APPLIED_BY']}"
        else:
            fix = "none logged"
        seen = sorted(runs[aid])
        last_seen = seen[-1]
        first_hit = min(r for r, ok in runs[aid].items() if ok)
        if runs[aid][last_seen]:
            check = f"**OPEN** (still leaks in round {last_seen})"
        elif last_seen > first_hit:
            check = f"closed, proven in round {last_seen}"
        else:
            check = "not re-checked yet"
        label = f"{aid} ({leak})" if leak else aid
        if m.get("SOURCE") and m["SOURCE"] != "library":
            label += f" · {m['SOURCE']}"
        out.append(f"| {_cell(label)} | {_cell(what)} | {_cell(tags)} | {_cell(fix)} | {_cell(check)} |")
    if not found:
        out.append("| none | No attack succeeded in any round. | | | |")
    out += [""]

    # ---- rounds
    out += ["## Rounds", "", "| Round | Leaks | Attacks run | Legit passed |", "|---|---|---|---|"]
    for r in board:
        out.append(f"| {r['ROUND_NO']} | {r['LEAKS'] or 0} | {r['ATTACKS'] or 0} | "
                   f"{r['LEGIT_PASSED'] or 0}/{r['LEGIT_TOTAL'] or 0} |")
    out += [""]

    blocked = sum(1 for a in attacks if int(a["ROUND_NO"]) == last_round and not a["SUCCEEDED"])
    out += [f"In the latest round, {blocked} attack(s) were tried and blocked (see the scoreboard's Rejected panel)."]
    if data.get("bouncer"):
        counts = {r["VERDICT"]: r["N"] for r in data["bouncer"]}
        out += ["", f"Bouncer package checks: {counts.get('BLOCK', 0)} blocked, {counts.get('WARN', 0)} warned, "
                    f"{counts.get('ALLOW', 0)} allowed."]
    out += ["", "---",
            "_Method: attacks and legitimate queries run as the low-privilege `LH_ANALYST` role (secondary roles off); "
            "fixes are Snowflake-native (masking policies, revoked grants, dropped scratch copies). "
            "Sample rows from attacks are deliberately left out of this report. Regulation tags are pointers for a "
            "reviewer, not legal advice._", ""]
    return "\n".join(out)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="report/audit_report.md")
    args = ap.parse_args()
    text = build(fetch())
    Path(args.out).write_text(text, encoding="utf-8")
    print(text)
    print(f"\nOK: wrote {args.out}")


if __name__ == "__main__":
    main()
