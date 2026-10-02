"""Run every attack YAML as LH_ANALYST, judge it, log to RESULTS.ATTACK_RUNS.

Contract: docs/CONTRACTS.md §6 (attack format) and §8 (results).
Run:  python -m referee.run_attacks [--round N]   (default: db.next_round)
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

import yaml

from leakhunter import config, db

ATTACK_DIRS = [Path("attacks/library"), Path("attacks/generated")]
PLACEHOLDER = "{PUBLIC_ZIP_TABLE}"


def load_attacks() -> list[dict]:
    attacks = []
    for folder in ATTACK_DIRS:
        for path in sorted(folder.glob("*.yaml")):
            with open(path, encoding="utf-8") as f:
                attack = yaml.safe_load(f)
            if isinstance(attack, dict) and attack.get("id"):
                attack["_path"] = str(path)
                attacks.append(attack)
    return attacks


def prepare_sql(sql: str) -> str:
    """Fill in placeholders. Raises ValueError if something can't be resolved."""
    if PLACEHOLDER in sql:
        if not config.PUBLIC_ZIP_TABLE:
            raise ValueError("LH_PUBLIC_ZIP_TABLE is not set (see docs/CONTRACTS.md section 4)")
        sql = sql.replace(PLACEHOLDER, config.PUBLIC_ZIP_TABLE)
    leftover = re.search(r"<[A-Z_]+>", sql)
    if leftover:
        raise ValueError(f"unfilled placeholder {leftover.group(0)} in attack SQL")
    return sql.strip().rstrip(";").strip()


def _column_values(cols: list[str], rows: list[tuple], column: str) -> list | None:
    upper = [c.upper() for c in cols]
    if column.upper() not in upper:
        return None
    i = upper.index(column.upper())
    return [r[i] for r in rows]


def judge(success: dict, cols: list[str], rows: list[tuple]) -> bool:
    """Apply a CONTRACTS §6 success rule to a result set."""
    kind = success.get("type", "nonempty")
    if kind == "nonempty":
        return len(rows) > 0
    values = _column_values(cols, rows, success.get("column", ""))
    if not values:
        return False
    if kind == "regex":
        pattern = re.compile(success["pattern"])
        return any(v is not None and pattern.fullmatch(str(v)) for v in values)
    if kind == "min_value":
        try:
            return float(values[0]) >= float(success.get("threshold", 1))
        except (TypeError, ValueError):
            return False
    raise ValueError(f"unknown success type: {kind}")


def _run_sql(analyst_conn, attack: dict, sql: str) -> dict:
    if not db.is_read_only(sql):
        return {"sql": sql, "succeeded": False, "rows": 0, "evidence": "",
                "error": "rejected: attack SQL must be a single SELECT / WITH / SHOW"}
    try:
        cols, rows = db.query(analyst_conn, sql)
    except Exception as e:  # permission denied, invalid SQL, ... all count as not succeeded
        return {"sql": sql, "succeeded": False, "rows": 0, "evidence": "", "error": str(e)}
    return {"sql": sql, "succeeded": judge(attack.get("success", {}), cols, rows),
            "rows": len(rows), "evidence": db.evidence(cols, rows), "error": ""}


def _run_sweep(analyst_conn, attack: dict) -> dict:
    """List every column the analyst can see matching column_pattern, sample 5 rows of each."""
    pattern = attack.get("column_pattern", "%SSN%")
    list_sql = (f"SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME FROM {config.DATABASE}.INFORMATION_SCHEMA.COLUMNS "
                f"WHERE COLUMN_NAME ILIKE %(p)s AND TABLE_SCHEMA <> 'INFORMATION_SCHEMA' ORDER BY 1, 2, 3")
    try:
        _, targets = db.query(analyst_conn, list_sql, {"p": pattern})
    except Exception as e:
        return {"sql": list_sql, "succeeded": False, "rows": 0, "evidence": "", "error": str(e)}

    success = dict(attack.get("success", {}))
    hits, errors, total_rows, tried = [], [], 0, []
    for schema, table, column in targets:
        sql = f'SELECT "{column}" FROM {config.DATABASE}."{schema}"."{table}" LIMIT 5'
        tried.append(sql)
        try:
            cols, rows = db.query(analyst_conn, sql)
        except Exception as e:
            errors.append(f"{schema}.{table}.{column}: {e}")
            continue
        total_rows += len(rows)
        # The rule's column is the matched column, whatever it's called in this table.
        if judge({**success, "column": column}, cols, rows):
            hits.append(f"{schema}.{table}.{column}: " + ", ".join(str(r[0]) for r in rows[:3]))

    return {"sql": "\n".join(tried) or list_sql, "succeeded": bool(hits), "rows": total_rows,
            "evidence": ("\n".join(hits) or f"{len(targets)} columns checked, none readable")[:300],
            "error": "\n".join(errors)}


def _run_chatbot(attack: dict) -> dict:
    prompt = attack.get("prompt", "")
    try:
        from chatbot import bot  # stretch module; may not exist yet
        cols, rows = bot.ask(prompt)
    except Exception as e:
        return {"sql": prompt, "succeeded": False, "rows": 0, "evidence": "", "error": f"chatbot: {e}"}
    return {"sql": prompt, "succeeded": judge(attack.get("success", {}), cols, rows),
            "rows": len(rows), "evidence": db.evidence(cols, rows), "error": ""}


def run_attack(analyst_conn, attack: dict) -> dict:
    """Run one attack, return {sql, succeeded, rows, evidence, error}. Never raises."""
    technique = attack.get("technique", "direct_sql")
    if technique == "sweep":
        return _run_sweep(analyst_conn, attack)
    if technique == "chatbot":
        return _run_chatbot(attack)
    raw = attack.get("sql", "")
    try:
        sql = prepare_sql(raw)
    except ValueError as e:
        return {"sql": raw, "succeeded": False, "rows": 0, "evidence": "", "error": str(e)}
    return _run_sql(analyst_conn, attack, sql)


def run_all(admin_conn, analyst_conn, round_no: int, verbose: bool = True) -> list[dict]:
    results = []
    for attack in load_attacks():
        r = run_attack(analyst_conn, attack)
        db.log_attack_run(admin_conn, round_no=round_no, attack=attack, sql_text=r["sql"],
                          succeeded=r["succeeded"], rows_returned=r["rows"],
                          evidence_text=r["evidence"], error=r["error"])
        results.append({"id": attack["id"], **r})
        if verbose:
            status = "LEAK " if r["succeeded"] else ("error" if r["error"] else "safe ")
            note = r["error"].splitlines()[0][:90] if r["error"] else ""
            print(f"  [{status}] {attack['id']:<5} {attack.get('goal', '')[:60]}  {note}")
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--round", type=int, help="round number (default: next round)")
    args = parser.parse_args()
    admin, analyst = db.connect(db.ADMIN), db.connect(db.ANALYST)
    try:
        round_no = args.round or db.next_round(admin)
        print(f"Round {round_no}: attacks")
        results = run_all(admin, analyst, round_no)
        print(f"Round {round_no}: leaks {sum(r['succeeded'] for r in results)}/{len(results)}")
    finally:
        admin.close()
        analyst.close()


if __name__ == "__main__":
    main()
