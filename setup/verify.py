"""Self-check for Manav's part, independent of the referee. Writes NOTHING to RESULTS.

Runs every library attack and every legit query as LH_ANALYST (secondary roles NONE) and
compares with what should happen.

    python -m setup.verify --expect planted   # after plant_leaks: planted leaks succeed, others fail
    python -m setup.verify --expect closed    # after fixes: every attack fails
    python -m setup.verify                    # just print the table

Exit code 1 if any expectation fails or any legit query fails.
Skips A03 until its SQL has no placeholders (needs the public ZIP table, CONTRACTS §4).
"""
from __future__ import annotations

import argparse
import glob
import re
import sys

import yaml

from leakhunter import db

# Which planted leak makes each library attack succeed. A07 (SSN sweep) hits L1 and L5.
ATTACK_LEAKS = {"A01": {"L1"}, "A02": {"L2"}, "A03": {"L3"}, "A04": {"L4"}, "A05": {"L5"},
                "A06": {"L6"}, "A07": {"L1", "L5"}}
_IDENT = re.compile(r"^[A-Z_][A-Z0-9_$]*$")


def check_success(spec: dict, cols: list[str], rows: list[tuple]) -> bool:
    kind = spec.get("type")
    upper = [x.upper() for x in cols]
    if kind == "nonempty":
        return len(rows) > 0
    col = str(spec.get("column", "")).upper()
    if col not in upper or not rows:
        return False
    i = upper.index(col)
    if kind == "regex":
        pat = re.compile(spec["pattern"])
        return any(v is not None and pat.fullmatch(str(v)) for v in (r[i] for r in rows))
    if kind == "min_value":
        try:
            return float(rows[0][i]) >= float(spec.get("threshold", 1))
        except (TypeError, ValueError):
            return False
    raise ValueError(f"unknown success type {kind!r}")


def run_attack(conn, a: dict) -> tuple[bool | None, str]:
    """(succeeded, note). None = skipped."""
    if a.get("technique") == "sweep":
        _, cols = db.query(conn,
            "SELECT C.TABLE_SCHEMA, C.TABLE_NAME, C.COLUMN_NAME FROM LEAKHUNTER.INFORMATION_SCHEMA.COLUMNS C "
            "WHERE C.COLUMN_NAME ILIKE %(p)s AND C.TABLE_SCHEMA <> 'INFORMATION_SCHEMA'", {"p": a["column_pattern"]})
        hits = []
        for schema, table, column in cols:
            if not all(_IDENT.match(str(x)) for x in (schema, table, column)):
                continue
            names, rows = db.query(conn, f'SELECT "{column}" AS "{a["success"]["column"]}" '
                                         f'FROM LEAKHUNTER."{schema}"."{table}" LIMIT 5')
            if check_success(a["success"], names, rows):
                hits.append(f"{schema}.{table}.{column}")
        return bool(hits), ", ".join(hits)
    sql = a.get("sql", "")
    if not sql or "{" in sql or "<" in sql:
        return None, "skipped (placeholder SQL)"
    if not db.is_read_only(sql):
        return None, "skipped (not read-only)"
    try:
        cols, rows = db.query(conn, sql)
    except Exception as e:  # a failed query is "not succeeded"
        return False, f"error: {str(e).splitlines()[0][:80]}"
    return check_success(a["success"], cols, rows), f"{len(rows)} rows"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--expect", choices=["planted", "closed"])
    args = ap.parse_args()

    planted: set[str] = set()
    if args.expect == "planted":
        admin = db.connect(db.ADMIN)
        _, rows = db.query(admin, "SELECT LEAK_ID FROM LEAKHUNTER.RESULTS.PLANTED")
        admin.close()
        planted = {r[0] for r in rows}
        print(f"Planted per RESULTS.PLANTED: {sorted(planted)}")

    conn = db.connect(db.ANALYST)
    _, who = db.query(conn, "SELECT CURRENT_ROLE(), IS_ROLE_IN_SESSION('LH_ADMIN')")
    if who[0][0] != db.ANALYST or who[0][1]:
        sys.exit(f"ABORT: session is {who[0]} — attacks must run as LH_ANALYST without LH_ADMIN")

    failures = 0
    print(f"\n{'ATTACK':7}{'RESULT':10}{'EXPECTED':10}NOTE")
    for path in sorted(glob.glob("attacks/library/*.yaml")):
        with open(path, encoding="utf-8") as f:
            a = yaml.safe_load(f)
        ok, note = run_attack(conn, a)
        expected = None
        if args.expect == "closed":
            expected = False
        elif args.expect == "planted":
            expected = bool(ATTACK_LEAKS.get(a["id"], set()) & planted)
        res = "skip" if ok is None else ("LEAK" if ok else "blocked")
        exp = "" if expected is None or ok is None else ("LEAK" if expected else "blocked")
        bad = ok is not None and expected is not None and ok != expected
        failures += bad
        print(f"{a['id']:7}{res:10}{exp:10}{'<-- MISMATCH  ' if bad else ''}{note}")

    print(f"\n{'QUERY':7}{'RESULT':10}NOTE")
    with open("legit/queries.yaml", encoding="utf-8") as f:
        for q in yaml.safe_load(f) or []:
            try:
                _, rows = db.query(conn, q["sql"])
                passed = len(rows) > 0 if q.get("expect", "nonempty") == "nonempty" else True
                note = f"{len(rows)} rows"
            except Exception as e:
                passed, note = False, f"error: {str(e).splitlines()[0][:80]}"
            failures += not passed
            print(f"{q['id']:7}{'pass' if passed else 'FAIL':10}{note}  {q.get('description', '')}")
    conn.close()

    print("\nALL GOOD" if failures == 0 else f"\n{failures} problem(s)")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
