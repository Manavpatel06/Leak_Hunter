"""Plant leaks L1-L6 (CONTRACTS §5). Runs as LH_ADMIN. Idempotent.

    python -m setup.plant_leaks --all                 # demo default: open all six
    python -m setup.plant_leaks --random 3 --seed 7   # open 3 random leaks, close the rest
    python -m setup.plant_leaks --only L1,L4          # open exactly these, close the rest
    python -m setup.plant_leaks --all --dry-run       # print the SQL, change nothing

Every leak NOT selected is put in its fixed state, so the attacks that succeed are exactly the
planted ones. The answer key goes to RESULTS.PLANTED (replaced on every run; analyst can't read it).
"""
from __future__ import annotations

import argparse
import random

from leakhunter import db
from setup import common as c

LEAKS = {
    "L1": "Patient SSNs readable (no mask on PATIENTS.SSN)",
    "L2": "Salaries by name (no mask on EMPLOYEES.FULL_NAME)",
    "L3": "Re-identification: 'anonymized' view PATIENT_DEMOGRAPHICS with raw ZIP + DOB + SEX",
    "L4": "Role too broad: LH_HR granted to LH_ANALYST (reads EMPLOYEE_REVIEWS)",
    "L5": "Forgotten export: SCRATCH.PATIENTS_EXPORT_OLD raw copy readable by analyst",
    "L6": "Harmless tables joined: view VISIT_DETAILS exposes patient name + diagnosis",
}

# One row per patient (latest visit), so (ZIP, birth year, sex) uniqueness == one person.
DEMOGRAPHICS_SQL = f"""CREATE OR REPLACE VIEW {c.DEMOGRAPHICS_VIEW}
  COMMENT = 'De-identified research extract (no names, no SSNs)' AS
SELECT P.PATIENT_ID, P.DOB, P.SEX, P.ZIP, V.DIAGNOSIS_DESC
FROM {c.PATIENTS} P JOIN {c.VISITS} V ON V.PATIENT_ID = P.PATIENT_ID
QUALIFY ROW_NUMBER() OVER (PARTITION BY P.PATIENT_ID ORDER BY V.VISIT_DATE DESC, V.VISIT_ID DESC) = 1"""

VISIT_DETAILS_SQL = f"""CREATE OR REPLACE VIEW {c.VISIT_DETAILS_VIEW}
  COMMENT = 'Reporting view for department dashboards' AS
SELECT V.VISIT_ID, V.VISIT_DATE, V.DEPARTMENT, P.FULL_NAME, V.DIAGNOSIS_DESC, V.COST
FROM {c.VISITS} V JOIN {c.PATIENTS} P ON P.PATIENT_ID = V.PATIENT_ID"""


def open_leak(conn, leak: str, dry: bool) -> None:
    if leak == "L1":
        c.unset_mask(conn, c.PATIENTS, "SSN", dry)
    elif leak == "L2":
        c.unset_mask(conn, c.EMPLOYEES, "FULL_NAME", dry)
    elif leak == "L3":
        c.run(conn, DEMOGRAPHICS_SQL, dry)
        c.run(conn, f"GRANT SELECT ON VIEW {c.DEMOGRAPHICS_VIEW} TO ROLE {c.ANALYST}", dry)
        c.unset_mask(conn, c.PATIENTS, "ZIP", dry)
        c.unset_mask(conn, c.PATIENTS, "DOB", dry)
    elif leak == "L4":
        c.run(conn, f"GRANT ROLE {c.HR} TO ROLE {c.ANALYST}", dry)
    elif leak == "L5":
        # Made by an admin, so it holds raw values even if PATIENTS is masked later.
        c.run(conn, f"CREATE OR REPLACE TABLE {c.EXPORT_OLD} "
                    f"COMMENT = 'tmp export for Q3 analysis - delete after' AS SELECT * FROM {c.PATIENTS}", dry)
        c.run(conn, f"GRANT USAGE ON SCHEMA {c.SCRATCH} TO ROLE {c.ANALYST}", dry)
        c.run(conn, f"GRANT SELECT ON TABLE {c.EXPORT_OLD} TO ROLE {c.ANALYST}", dry)
    elif leak == "L6":
        c.run(conn, VISIT_DETAILS_SQL, dry)
        c.run(conn, f"GRANT SELECT ON VIEW {c.VISIT_DETAILS_VIEW} TO ROLE {c.ANALYST}", dry)
        c.unset_mask(conn, c.PATIENTS, "FULL_NAME", dry)


def close_leak(conn, leak: str, dry: bool) -> None:
    """The fixed state for a leak we are not planting this run."""
    if leak == "L1":
        c.set_mask(conn, c.PATIENTS, "SSN", c.MASK_SSN, dry)
    elif leak == "L2":
        c.set_mask(conn, c.EMPLOYEES, "FULL_NAME", c.MASK_NAME, dry)
    elif leak == "L3":
        c.set_mask(conn, c.PATIENTS, "ZIP", c.MASK_ZIP, dry)
        c.set_mask(conn, c.PATIENTS, "DOB", c.MASK_DOB, dry)
        c.run(conn, f"DROP VIEW IF EXISTS {c.DEMOGRAPHICS_VIEW}", dry)
    elif leak == "L4":
        c.revoke_hr(conn, dry)
    elif leak == "L5":
        c.revoke_scratch(conn, dry)
        c.drop_scratch_object(conn, c.EXPORT_OLD, "TABLE", dry)
    elif leak == "L6":
        c.set_mask(conn, c.PATIENTS, "FULL_NAME", c.MASK_NAME, dry)
        c.run(conn, f"DROP VIEW IF EXISTS {c.VISIT_DETAILS_VIEW}", dry)


def choose(args) -> list[str]:
    if args.all:
        return list(LEAKS)
    if args.only:
        chosen = [x.strip().upper() for x in args.only.split(",") if x.strip()]
        bad = [x for x in chosen if x not in LEAKS]
        if bad:
            raise SystemExit(f"unknown leak id(s): {bad}; valid: {list(LEAKS)}")
        return sorted(set(chosen))
    if not 1 <= args.random <= len(LEAKS):
        raise SystemExit(f"--random must be 1..{len(LEAKS)}")
    return sorted(random.Random(args.seed).sample(list(LEAKS), args.random))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--all", action="store_true")
    g.add_argument("--random", type=int, metavar="N")
    g.add_argument("--only", metavar="L1,L3")
    ap.add_argument("--seed", type=int, default=None, help="seed for --random")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    chosen = choose(args)
    print(f"Planting {chosen} (closing the rest){' [DRY RUN]' if args.dry_run else ''}")
    conn = db.connect(db.ADMIN)
    try:
        c.ensure_baseline(conn, args.dry_run)
        for leak in LEAKS:
            print(f"- {leak} {'OPEN ' if leak in chosen else 'close'}: {LEAKS[leak]}")
            (open_leak if leak in chosen else close_leak)(conn, leak, args.dry_run)
        if not args.dry_run:
            db.query(conn, "DELETE FROM LEAKHUNTER.RESULTS.PLANTED")
            for leak in chosen:
                db.query(conn, "INSERT INTO LEAKHUNTER.RESULTS.PLANTED (LEAK_ID, DESCRIPTION) "
                               "VALUES (%(id)s, %(d)s)", {"id": leak, "d": LEAKS[leak]})
    finally:
        conn.close()
    print(f"OK: planted {chosen}. Check with: python -m setup.verify --expect planted")


if __name__ == "__main__":
    main()
