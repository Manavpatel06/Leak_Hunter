"""Shared Snowflake helpers. Every connection and every RESULTS write goes through here.

Contract: docs/CONTRACTS.md §2 and §8.
Smoke test:  python -m leakhunter.db
"""
from __future__ import annotations

import re
import uuid

import snowflake.connector

from leakhunter import config

ADMIN, ANALYST = config.ADMIN, config.ANALYST
_READ_ONLY = re.compile(r"^\s*(select|with|show)\b", re.IGNORECASE)


def connect(role: str):
    """Open a connection as exactly one role. Secondary roles are always disabled,
    otherwise the service user's other roles leak into attack sessions."""
    conn = snowflake.connector.connect(role=role, **config.snowflake_params())
    cur = conn.cursor()
    cur.execute("USE SECONDARY ROLES NONE")
    cur.execute(f"USE WAREHOUSE {config.WAREHOUSE}")
    cur.close()
    return conn


def query(conn, sql: str, params: dict | None = None) -> tuple[list[str], list[tuple]]:
    """Run one statement, return (column_names, rows)."""
    cur = conn.cursor()
    try:
        # Only pass params when given: a '%' in LIKE patterns would otherwise break pyformat.
        if params:
            cur.execute(sql, params)
        else:
            cur.execute(sql)
        cols = [d[0] for d in (cur.description or [])]
        rows = cur.fetchall() if cur.description else []
        return cols, rows
    finally:
        cur.close()


def is_read_only(sql: str) -> bool:
    """Attack SQL must be SELECT / WITH / SHOW and a single statement."""
    stripped = sql.strip().rstrip(";")
    return bool(_READ_ONLY.match(stripped)) and ";" not in stripped


def evidence(cols: list[str], rows: list[tuple], limit_rows: int = 3, limit_chars: int = 300) -> str:
    """First few rows as short text for the log (contract: max 3 rows, 300 chars)."""
    lines = [", ".join(cols)] + [", ".join(str(v) for v in r) for r in rows[:limit_rows]]
    return "\n".join(lines)[:limit_chars]


def next_round(admin_conn) -> int:
    _, rows = query(admin_conn, "SELECT COALESCE(MAX(ROUND_NO), 0) + 1 FROM LEAKHUNTER.RESULTS.ATTACK_RUNS")
    return int(rows[0][0])


def current_round(admin_conn) -> int:
    _, rows = query(admin_conn, "SELECT COALESCE(MAX(ROUND_NO), 0) FROM LEAKHUNTER.RESULTS.ATTACK_RUNS")
    return int(rows[0][0])


def _new_id() -> str:
    return uuid.uuid4().hex[:12]


def log_attack_run(admin_conn, *, round_no: int, attack: dict, sql_text: str, succeeded: bool,
                   rows_returned: int = 0, evidence_text: str = "", error: str = "") -> None:
    query(admin_conn,
          """INSERT INTO LEAKHUNTER.RESULTS.ATTACK_RUNS
             (RUN_ID, ROUND_NO, ATTACK_ID, GOAL, TECHNIQUE, SOURCE, TARGETS_LEAK, SQL_TEXT,
              SUCCEEDED, ROWS_RETURNED, EVIDENCE, ERROR)
             VALUES (%(run_id)s, %(round_no)s, %(attack_id)s, %(goal)s, %(technique)s, %(source)s,
                     %(targets_leak)s, %(sql_text)s, %(succeeded)s, %(rows)s, %(evidence)s, %(error)s)""",
          {"run_id": _new_id(), "round_no": round_no, "attack_id": attack["id"],
           "goal": attack.get("goal", ""), "technique": attack.get("technique", ""),
           "source": attack.get("source", ""), "targets_leak": attack.get("targets_leak", ""),
           "sql_text": sql_text, "succeeded": succeeded, "rows": rows_returned,
           "evidence": evidence_text, "error": error[:1000]})


def log_legit_run(admin_conn, *, round_no: int, query_id: str, description: str,
                  passed: bool, error: str = "") -> None:
    query(admin_conn,
          """INSERT INTO LEAKHUNTER.RESULTS.LEGIT_RUNS
             (RUN_ID, ROUND_NO, QUERY_ID, DESCRIPTION, PASSED, ERROR)
             VALUES (%(run_id)s, %(round_no)s, %(qid)s, %(desc)s, %(passed)s, %(error)s)""",
          {"run_id": _new_id(), "round_no": round_no, "qid": query_id, "desc": description,
           "passed": passed, "error": error[:1000]})


def log_fix(admin_conn, *, round_no: int, attack_id: str, fix_type: str, sql_applied: str,
            rationale: str, applied_by: str) -> None:
    query(admin_conn,
          """INSERT INTO LEAKHUNTER.RESULTS.FIXES
             (FIX_ID, ROUND_NO, ATTACK_ID, FIX_TYPE, SQL_APPLIED, RATIONALE, APPLIED_BY)
             VALUES (%(fix_id)s, %(round_no)s, %(attack_id)s, %(fix_type)s, %(sql)s, %(why)s, %(by)s)""",
          {"fix_id": _new_id(), "round_no": round_no, "attack_id": attack_id, "fix_type": fix_type,
           "sql": sql_applied, "why": rationale, "by": applied_by})


if __name__ == "__main__":
    for role in (ADMIN, ANALYST):
        c = connect(role)
        cols, rows = query(c, "SELECT CURRENT_ROLE(), CURRENT_WAREHOUSE(), CURRENT_DATABASE()")
        print(f"{role}: connected ->", dict(zip(cols, rows[0])))
        c.close()
    print("OK: both roles connect.")
