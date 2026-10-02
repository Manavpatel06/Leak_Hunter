"""Defender fallback (owner: Manav). Use if CoCo is unavailable or slow on stage.

Reads RESULTS.LEAK_LOG (successful attacks in the latest round), maps each to the smallest
pii-guardian playbook fix, applies it as LH_ADMIN, and logs one RESULTS.FIXES row per attack
it closes (APPLIED_BY = 'script').

    python -m defender.apply_fixes                  # fix everything in LEAK_LOG
    python -m defender.apply_fixes --dry-run        # show the plan + SQL, change nothing
    python -m defender.apply_fixes --from-planted   # rehearsal without the referee: fix RESULTS.PLANTED

Safety:
- Attack SQL in the log is untrusted (Gemma / judge). It is only pattern-matched, never executed.
- Only the playbook's fixed statements run. Identifiers found at runtime are validated first.
- Never drops outside LEAKHUNTER.SCRATCH, never touches baseline analyst SELECT grants,
  never edits ATTACK_RUNS / LEGIT_RUNS (pii-guardian hard rules).
"""
from __future__ import annotations

import argparse
import re

from leakhunter import db
from setup import common as c

SSN_RE = re.compile(r"^\d{3}-\d{2}-\d{4}$")

# Leak -> (fix type, rationale). CONTRACTS §5 + skills/pii-guardian/references/fix-playbook.md
LEAK_FIX = {
    "L1": ("masking", "Mask PATIENTS.SSN at the base column; analyst sees only the last 4 digits."),
    "L2": ("masking", "Mask EMPLOYEES.FULL_NAME, keep SALARY visible so salary averages still work."),
    "L3": ("masking", "Generalize quasi-identifiers: ZIP to 3 digits, DOB to birth year; masks follow the "
                      "columns into PATIENT_DEMOGRAPHICS, so the public-data join no longer singles anyone out."),
    "L4": ("revoke", "Analyst inherited LH_HR; revoke the role grant (least privilege)."),
    "L5": ("drop_scratch", "Raw admin-made copy in SCRATCH; masking the source never protects a copy. "
                           "Revoke analyst access to SCRATCH and drop the copy."),
    "L6": ("masking", "Mask PATIENTS.FULL_NAME; the mask follows the column into VISIT_DETAILS, so "
                      "diagnoses stay usable but are no longer tied to names."),
}
ATTACK_TO_LEAK = {"A01": "L1", "A02": "L2", "A03": "L3", "A04": "L4", "A05": "L5", "A06": "L6"}


class Fixer:
    """Applies root-cause fixes once per run and remembers what each one executed."""

    def __init__(self, admin, dry: bool):
        self.admin, self.dry = admin, dry
        self.done: dict = {}   # root-cause key -> SQL executed this run (cached result)
        self._analyst = None

    def _once(self, key: str, fn) -> list[str]:
        if key not in self.done:
            self.done[key] = fn()
        return self.done[key]

    def mask(self, table: str, col: str, policy: str) -> list[str]:
        return self._once(f"mask:{table}.{col}", lambda: c.set_mask(self.admin, table, col, policy, self.dry))

    def revoke_hr(self) -> list[str]:
        return self._once("revoke_hr", lambda: c.revoke_hr(self.admin, self.dry))

    def close_scratch(self, table: str | None = None) -> list[str]:
        sql = list(self._once("revoke_scratch", lambda: c.revoke_scratch(self.admin, self.dry)))
        if table:
            sql += self._once(f"drop:{table}", lambda: c.drop_scratch_object(self.admin, table, "TABLE", self.dry))
        return sql

    def for_leak(self, leak: str) -> list[str]:
        if leak == "L1":
            return self.mask(c.PATIENTS, "SSN", c.MASK_SSN)
        if leak == "L2":
            return self.mask(c.EMPLOYEES, "FULL_NAME", c.MASK_NAME)
        if leak == "L3":
            return self.mask(c.PATIENTS, "ZIP", c.MASK_ZIP) + self.mask(c.PATIENTS, "DOB", c.MASK_DOB)
        if leak == "L4":
            return self.revoke_hr()
        if leak == "L5":
            return self.close_scratch(c.EXPORT_OLD)
        if leak == "L6":
            return self.mask(c.PATIENTS, "FULL_NAME", c.MASK_NAME)
        raise ValueError(leak)

    # ---- for attacks that are not one of the six library leaks (sweep, Gemma, judge) ----
    def analyst(self):
        if self._analyst is None:
            self._analyst = db.connect(db.ANALYST)
        return self._analyst

    def ssn_sweep(self) -> tuple[list[str], list[str]]:
        """Find every SSN-like column the analyst can read in clear text and close it.
        Returns (sql_applied, notes). Runs once per defender run (cached)."""
        if "ssn_sweep" not in self.done:
            self.done["ssn_sweep"] = self._ssn_sweep()
        return self.done["ssn_sweep"]

    def _ssn_sweep(self) -> tuple[list[str], list[str]]:
        conn = self.analyst()
        _, cols = db.query(conn,
            "SELECT C.TABLE_SCHEMA, C.TABLE_NAME, C.COLUMN_NAME, T.TABLE_TYPE "
            "FROM LEAKHUNTER.INFORMATION_SCHEMA.COLUMNS C JOIN LEAKHUNTER.INFORMATION_SCHEMA.TABLES T "
            "  ON T.TABLE_SCHEMA = C.TABLE_SCHEMA AND T.TABLE_NAME = C.TABLE_NAME "
            "WHERE C.COLUMN_NAME ILIKE '%SSN%' AND C.TABLE_SCHEMA <> 'INFORMATION_SCHEMA'")
        sql, notes = [], []
        for schema, table, column, ttype in cols:
            try:
                schema, table, column = (c.safe_ident(x) for x in (schema, table, column))
            except ValueError as e:
                notes.append(f"skipped odd name ({e}); fix by hand")
                continue
            fq = f"LEAKHUNTER.{schema}.{table}"
            try:
                _, rows = db.query(conn, f'SELECT "{column}" FROM {fq} LIMIT 5')
            except Exception:
                continue
            if not any(v is not None and SSN_RE.match(str(v)) for (v,) in rows):
                continue
            if schema == "SCRATCH":
                sql += self.close_scratch(fq if ttype == "BASE TABLE" else None)
                notes.append(f"{fq}.{column} readable in SCRATCH -> revoke + drop")
            elif schema == "DATA" and ttype == "BASE TABLE":
                sql += self.mask(fq, column, c.MASK_SSN)
                notes.append(f"{fq}.{column} unmasked -> MASK_SSN")
            else:
                notes.append(f"RECOMMENDATION: {fq}.{column} exposes SSNs ({ttype}); fix the base table by hand")
        return sql, notes

    def heuristic(self, row: dict) -> tuple[list[str], list[str], str]:
        """Root causes for an attack that is not one of the six library leaks (sweep, Gemma, judge),
        matched from its text, then confirmed against the live state. Returns (sql, notes, fix_type)."""
        text = " ".join(str(row.get(k) or "") for k in ("SQL_TEXT", "GOAL", "TECHNIQUE", "EVIDENCE")).upper()
        tech = str(row.get("TECHNIQUE") or "").lower()
        sql, notes, types = [], [], []
        if tech == "sweep" or "SSN" in text or "SCRATCH" in text:
            s, n = self.ssn_sweep()
            sql += s
            notes += n
            if s:
                types.append("drop_scratch" if any("SCRATCH" in x for x in s) else "masking")
        if tech != "sweep":
            for t in sorted(set(re.findall(r'SCRATCH\."?([A-Z_][A-Z0-9_$]*)', text))):
                sql += self.close_scratch(f"{c.SCRATCH}.{t}")
                types.append("drop_scratch")
            if "EMPLOYEE_REVIEWS" in text or "MANAGER_NOTES" in text or tech == "role_escalation":
                sql += self.revoke_hr()
                types.append("revoke")
            if "FULL_NAME" in text and ("EMPLOYEES" in text or "SALARY" in text):
                sql += self.for_leak("L2")
                types.append("masking")
            if "FULL_NAME" in text and ("PATIENT" in text or "DIAGNOS" in text or "VISIT" in text):
                sql += self.for_leak("L6")
                types.append("masking")
            if tech == "reidentification" or "PATIENT_DEMOGRAPHICS" in text or re.search(r"\b(ZIP|DOB)\b", text):
                sql += self.for_leak("L3")
                types.append("masking")
        seen, uniq = set(), []
        for x in sql:                      # same statement may be reached twice
            if x not in seen:
                seen.add(x)
                uniq.append(x)
        return uniq, notes, (types[0] if types else "masking")

    def close(self):
        if self._analyst is not None:
            self._analyst.close()


def _leak_of(row: dict) -> str:
    return (str(row.get("TARGETS_LEAK") or "")).upper() or ATTACK_TO_LEAK.get(row["ATTACK_ID"], "")


def load_targets(admin, from_planted: bool) -> list[dict]:
    if from_planted:
        _, rows = db.query(admin, "SELECT LEAK_ID FROM LEAKHUNTER.RESULTS.PLANTED ORDER BY LEAK_ID")
        rnd = db.current_round(admin)
        inv = {v: k for k, v in ATTACK_TO_LEAK.items()}
        return [{"ATTACK_ID": inv[r[0]], "TARGETS_LEAK": r[0], "ROUND_NO": rnd, "TECHNIQUE": ""}
                for r in rows if r[0] in inv]
    cols, rows = db.query(admin, "SELECT * FROM LEAKHUNTER.RESULTS.LEAK_LOG ORDER BY ATTACK_ID, RAN_AT")
    seen, out = set(), []
    for r in rows:
        rec = dict(zip(cols, r))
        if rec["ATTACK_ID"] not in seen:          # one fix entry per attack
            seen.add(rec["ATTACK_ID"])
            out.append(rec)
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--from-planted", action="store_true")
    args = ap.parse_args()

    admin = db.connect(db.ADMIN)
    fixer = Fixer(admin, args.dry_run)
    logged, warnings = 0, []
    try:
        targets = load_targets(admin, args.from_planted)
        if not targets:
            print("Nothing to fix: LEAK_LOG is empty for the latest round.")
            return
        print(f"{len(targets)} leaking attack(s) in round {targets[0]['ROUND_NO']}"
              f"{' [DRY RUN]' if args.dry_run else ''}")
        # Unrecognized attacks first: the SSN sweep then fixes shared root causes (e.g. PATIENTS.SSN,
        # the SCRATCH export) and the library attacks reuse those cached fixes, so each attack
        # is logged with the SQL that actually closed it.
        targets.sort(key=lambda r: (_leak_of(r) in LEAK_FIX, r["ATTACK_ID"]))
        for row in targets:
            aid, leak = row["ATTACK_ID"], _leak_of(row)
            print(f"\n{aid} ({leak or row.get('TECHNIQUE') or 'unknown'})")
            if leak in LEAK_FIX:
                sql = fixer.for_leak(leak)
                fix_type, why = LEAK_FIX[leak]
            else:
                sql, notes, fix_type = fixer.heuristic(row)
                for n in notes:
                    print("  " + n)
                recs = [n for n in notes if n.startswith("RECOMMENDATION")]
                warnings += [f"{aid}: {r}" for r in recs]
                why = "; ".join(n for n in notes if n not in recs) or \
                      "Closed the root cause matched from the attack's target columns/objects."
            if not sql:
                print("  already fixed before this run; nothing applied, not logged")
                if leak not in LEAK_FIX:
                    warnings.append(f"{aid}: no open root cause found; re-run the round and look at it by hand")
                continue
            sql_text = ";\n".join(sql) + ";"
            if not args.dry_run:
                db.log_fix(admin, round_no=int(row["ROUND_NO"]), attack_id=aid, fix_type=fix_type,
                           sql_applied=sql_text, rationale=why, applied_by="script")
                logged += 1
    finally:
        fixer.close()
        admin.close()

    for w in warnings:
        print("WARNING:", w)
    print(f"\nOK: {logged} fix(es) logged. Next: python -m referee.run_round (expect 0 leaks, legit all pass)")


if __name__ == "__main__":
    main()
