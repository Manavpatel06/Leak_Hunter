"""Run every legit analyst query (legit/queries.yaml) as LH_ANALYST, log to RESULTS.LEGIT_RUNS.

Contract: docs/CONTRACTS.md §7 (query format) and §8 (results).
Run:  python -m referee.run_legit [--round N]   (default: latest attack round)
"""
from __future__ import annotations

import argparse
from pathlib import Path

import yaml

from leakhunter import db

QUERIES_FILE = Path("legit/queries.yaml")


def load_queries() -> list[dict]:
    with open(QUERIES_FILE, encoding="utf-8") as f:
        return [q for q in (yaml.safe_load(f) or []) if isinstance(q, dict) and q.get("id")]


def run_query(analyst_conn, q: dict) -> tuple[bool, str]:
    """Return (passed, error). nonempty: must return rows. no_error: must just run."""
    try:
        _, rows = db.query(analyst_conn, q["sql"].strip().rstrip(";"))
    except Exception as e:
        return False, str(e)
    if q.get("expect", "nonempty") == "nonempty" and not rows:
        return False, "returned no rows"
    return True, ""


def run_all(admin_conn, analyst_conn, round_no: int, verbose: bool = True) -> list[dict]:
    results = []
    for q in load_queries():
        passed, error = run_query(analyst_conn, q)
        db.log_legit_run(admin_conn, round_no=round_no, query_id=q["id"],
                         description=q.get("description", ""), passed=passed, error=error)
        results.append({"id": q["id"], "passed": passed, "error": error})
        if verbose:
            note = error.splitlines()[0][:90] if error else ""
            print(f"  [{'pass' if passed else 'FAIL'}] {q['id']:<4} {q.get('description', '')[:60]}  {note}")
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--round", type=int, help="round number (default: latest attack round)")
    args = parser.parse_args()
    admin, analyst = db.connect(db.ADMIN), db.connect(db.ANALYST)
    try:
        round_no = args.round or max(db.current_round(admin), 1)
        print(f"Round {round_no}: legit queries")
        results = run_all(admin, analyst, round_no)
        print(f"Round {round_no}: legit {sum(r['passed'] for r in results)}/{len(results)}")
    finally:
        admin.close()
        analyst.close()


if __name__ == "__main__":
    main()
