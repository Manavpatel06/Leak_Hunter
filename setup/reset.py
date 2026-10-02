"""Reset the warehouse to the 'nothing planted, nothing fixed' state for another rehearsal.
Runs as LH_ADMIN. Idempotent. Does NOT regenerate data.

    python -m setup.reset                    # reset + clear RESULTS tables
    python -m setup.reset --keep-results     # reset objects, keep the RESULTS history
    python -m setup.reset --dry-run

Then: python -m setup.plant_leaks --all
Keeps: data, baseline grants, and the baseline EMPLOYEES.SSN mask (not a planted leak).
"""
from __future__ import annotations

import argparse

from leakhunter import db
from setup import common as c

UNMASK = [(c.PATIENTS, "SSN"), (c.PATIENTS, "FULL_NAME"), (c.PATIENTS, "ZIP"), (c.PATIENTS, "DOB"),
          (c.EMPLOYEES, "FULL_NAME")]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--keep-results", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    dry = args.dry_run

    conn = db.connect(db.ADMIN)
    try:
        print("Masks off (planted-leak columns) ...")
        for table, col in UNMASK:
            c.unset_mask(conn, table, col, dry)
        print("Revoke planted grants ...")
        c.revoke_hr(conn, dry)
        c.revoke_scratch(conn, dry)
        print("Drop planted views + everything in SCRATCH (incl. judge exports) ...")
        c.run(conn, f"DROP VIEW IF EXISTS {c.DEMOGRAPHICS_VIEW}", dry)
        c.run(conn, f"DROP VIEW IF EXISTS {c.VISIT_DETAILS_VIEW}", dry)
        for kind, name in c.scratch_objects(conn):
            c.drop_scratch_object(conn, name, kind, dry)
        print("Baseline grants + EMPLOYEES.SSN mask ...")
        c.ensure_baseline(conn, dry)
        if not args.keep_results:
            print("Clear RESULTS ...")
            for t in c.RESULTS_TABLES:
                c.run(conn, f"TRUNCATE TABLE IF EXISTS LEAKHUNTER.RESULTS.{t}", dry)
    finally:
        conn.close()
    print("OK: reset done. Next: python -m setup.plant_leaks --all")


if __name__ == "__main__":
    main()
