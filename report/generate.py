"""Write report/audit_report.md: a one-page, plain-English audit of every leak found and fixed.

Run from the repo root:  python -m report.generate
Reads LEAKHUNTER.RESULTS as LH_ADMIN (CONTRACTS §8). Regulation tags come from
skills/pii-guardian/references/fix-playbook.md.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from leakhunter import db

ROOT = Path(__file__).resolve().parents[1]
PLAYBOOK = ROOT / "skills" / "pii-guardian" / "references" / "fix-playbook.md"
OUT = ROOT / "report" / "audit_report.md"

# Leak-type keyword in the playbook's "Regulation tags" table -> tag, used if the table can't be read.
FALLBACK_TAGS = {
    "patient": "HIPAA Privacy Rule (minimum necessary)",
    "re-identifiable": "HIPAA de-identification standard (45 CFR 164.514)",
    "employee": "GDPR Art. 5(1)(f) integrity and confidentiality; state privacy law",
    "over-broad": "GDPR Art. 32 security of processing; least-privilege control",
}
# Catalog leak (CONTRACTS §5) -> playbook leak-type keyword.
LEAK_KIND = {"L1": "patient", "L2": "employee", "L3": "re-identifiable",
             "L4": "over-broad", "L5": "over-broad", "L6": "patient"}
LEAK_TITLE = {"L1": "Patient SSNs readable", "L2": "Salaries readable by name",
              "L3": "\"Anonymized\" patients re-identifiable", "L4": "Analyst role too broad",
              "L5": "Forgotten raw export", "L6": "Names joined to diagnoses"}


def load_tags() -> dict[str, str]:
    """Parse the playbook's regulation table into {lowercase leak type: tag}."""
    try:
        text = PLAYBOOK.read_text(encoding="utf-8")
    except OSError:
        return {}
    section = text.split("## Regulation tags", 1)[-1] if "## Regulation tags" in text else ""
    tags = {}
    for line in section.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 2 and cells[0] and not set(cells[0]) <= set("-: ") and cells[0] != "Leak type":
            tags[cells[0].lower()] = cells[1]
    return tags


def tag_for(attack: dict, tags: dict[str, str]) -> str:
    """Pick the regulation tag for a leak: by catalog id, then technique, then goal wording."""
    kind = LEAK_KIND.get(attack.get("TARGETS_LEAK") or "")
    goal = (attack.get("GOAL") or "").lower()
    if not kind:
        if attack.get("TECHNIQUE") == "reidentification" or "identify" in goal:
            kind = "re-identifiable"
        elif attack.get("TECHNIQUE") in ("role_escalation", "sweep") or "export" in goal or "table" in goal:
            kind = "over-broad"
        elif "employee" in goal or "salary" in goal or "review" in goal:
            kind = "employee"
        else:
            kind = "patient"
    for leak_type, tag in tags.items():
        if kind in leak_type:
            return tag
    return FALLBACK_TAGS[kind]


def rows(conn, sql: str) -> list[dict]:
    cols, data = db.query(conn, sql)
    return [dict(zip(cols, r)) for r in data]


def build(conn) -> str:
    score = rows(conn, "SELECT ROUND_NO, LEAKS, ATTACKS, LEGIT_PASSED, LEGIT_TOTAL "
                       "FROM LEAKHUNTER.RESULTS.SCOREBOARD ORDER BY ROUND_NO")
    runs = rows(conn, "SELECT ROUND_NO, ATTACK_ID, GOAL, TECHNIQUE, SOURCE, TARGETS_LEAK, SUCCEEDED, ERROR "
                      "FROM LEAKHUNTER.RESULTS.ATTACK_RUNS ORDER BY ROUND_NO, ATTACK_ID")
    fixes = rows(conn, "SELECT ROUND_NO, ATTACK_ID, FIX_TYPE, SQL_APPLIED, RATIONALE, APPLIED_BY "
                       "FROM LEAKHUNTER.RESULTS.FIXES ORDER BY APPLIED_AT")
    tags = load_tags()
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    out = ["# LeakHunter audit report", "",
           f"Generated {now} from `LEAKHUNTER.RESULTS`. All data in this warehouse is synthetic.", ""]
    if not score:
        out.append("No rounds have been run yet, so there is nothing to report.")
        return "\n".join(out) + "\n"

    latest = score[-1]["ROUND_NO"]
    latest_result = {r["ATTACK_ID"]: r for r in runs if r["ROUND_NO"] == latest}

    # Every attack that succeeded at least once is a leak; keep the first round it was proven.
    leaks: dict[str, dict] = {}
    for r in runs:
        if r["SUCCEEDED"] and r["ATTACK_ID"] not in leaks:
            leaks[r["ATTACK_ID"]] = r

    out += ["## Leaks found", ""]
    if not leaks:
        out.append("No attack succeeded in any round. No leaks were found.")
    for attack_id, first in leaks.items():
        leak_id = first.get("TARGETS_LEAK") or ""
        title = LEAK_TITLE.get(leak_id, first["GOAL"])
        attack_fixes = [f for f in fixes if f["ATTACK_ID"] == attack_id]
        now_run = latest_result.get(attack_id)
        if now_run is None:
            status = f"**Not re-tested** (attack did not run in round {latest})."
        elif now_run["SUCCEEDED"] and first["ROUND_NO"] == latest:
            status = f"**Open**: found in round {latest}; not re-checked yet."
        elif now_run["SUCCEEDED"]:
            status = f"**Still open**: the attack still succeeds in round {latest}."
        else:
            status = f"**Closed**: the same attack fails in round {latest}."

        out += [f"### {attack_id}{f' ({leak_id})' if leak_id else ''}: {title}", "",
                f"- **What leaked:** {first['GOAL']} (proven in round {first['ROUND_NO']} by a "
                f"`{first['TECHNIQUE']}` attack from the {first['SOURCE']} set, running as the low-privilege "
                f"`LH_ANALYST` role).",
                f"- **Rule it breaks:** {tag_for(first, tags)}."]
        if attack_fixes:
            for f in attack_fixes:
                out.append(f"- **Fix ({f['FIX_TYPE']}, by {f['APPLIED_BY']}, after round {f['ROUND_NO']}):** "
                           f"{(f['RATIONALE'] or '').rstrip('.')}.")
                out.append(f"  `{' '.join((f['SQL_APPLIED'] or '').split())}`")
        else:
            out.append("- **Fix:** none logged yet.")
        out += [f"- **Re-check:** {status}", ""]

    first, last = score[0], score[-1]

    def legit(r: dict) -> str:
        return "not run" if r["LEGIT_TOTAL"] is None else f"{r['LEGIT_PASSED']}/{r['LEGIT_TOTAL']}"

    closed = sum(1 for a in leaks if a in latest_result and not latest_result[a]["SUCCEEDED"])
    out += ["## Summary", "",
            f"- **Rounds run:** {len(score)}",
            f"- **Leaks:** {first['LEAKS'] or 0} in round {first['ROUND_NO']} → "
            f"{last['LEAKS'] or 0} in round {last['ROUND_NO']} "
            f"({closed} of {len(leaks)} distinct leaks closed, {len(fixes)} fixes applied)",
            f"- **Legitimate analyst queries working:** {legit(first)} in round {first['ROUND_NO']} → "
            f"{legit(last)} in round {last['ROUND_NO']}", ""]
    if (last["LEAKS"] or 0) == 0 and last["LEGIT_TOTAL"] and last["LEGIT_PASSED"] == last["LEGIT_TOTAL"]:
        out.append("Every proven leak is closed and the legitimate workload still works.")
    out += ["", "_Regulation tags are plain-English pointers for discussion, not legal advice._"]
    return "\n".join(out) + "\n"


def main() -> None:
    conn = db.connect(db.ADMIN)
    try:
        text = build(conn)
    finally:
        conn.close()
    OUT.write_text(text, encoding="utf-8")
    print(f"Wrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
