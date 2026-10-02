"""Gemma (via Ollama) writes new attacks from the goals in attacks/goals.yaml.

For each goal Gemma sees the schema LH_ANALYST can see plus 3 library attacks as examples.
Each read-only SQL that runs is saved as attacks/generated/G###.yaml (CONTRACTS §6, source: gemma).
On a SQL error Gemma gets one retry with the error fed back.

Run:  python -m attacker.gemma_attacker            # every goal
      python -m attacker.gemma_attacker --goal 2   # one goal (1-based), e.g. live on stage
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

import ollama
import yaml

from leakhunter import config, db
from referee import run_attacks

GOALS_FILE = Path("attacks/goals.yaml")
OUT_DIR = Path("attacks/generated")
EXAMPLE_IDS = ("A01", "A02", "A06")

SYSTEM = """You are a red-team SQL attacker testing a Snowflake warehouse you are authorized to test.
All data is synthetic. You are logged in as a low-privilege analyst role.
Write exactly ONE read-only Snowflake SQL statement (SELECT or WITH) that achieves the goal.
Rules:
- Use only tables and columns from the schema below. Always fully qualify: DATABASE.SCHEMA.TABLE.
- The result MUST include a column named exactly {must_return} (use AS {must_return} if needed).
- End with LIMIT 10.
- Reply with only the SQL inside a ```sql code block. No explanation."""


def visible_schema(analyst_conn) -> str:
    """Every table/column the analyst can see, one line per table."""
    _, rows = db.query(analyst_conn,
                       f"SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, DATA_TYPE "
                       f"FROM {config.DATABASE}.INFORMATION_SCHEMA.COLUMNS "
                       f"WHERE TABLE_SCHEMA <> 'INFORMATION_SCHEMA' "
                       f"ORDER BY TABLE_SCHEMA, TABLE_NAME, ORDINAL_POSITION")
    tables: dict[str, list[str]] = {}
    for schema, table, column, dtype in rows:
        tables.setdefault(f"{config.DATABASE}.{schema}.{table}", []).append(f"{column} {dtype}")
    return "\n".join(f"{t}({', '.join(cols)})" for t, cols in tables.items())


def examples() -> str:
    by_id = {a["id"]: a for a in run_attacks.load_attacks()}
    return "\n\n".join(f"Goal: {by_id[i]['goal']}\n```sql\n{by_id[i]['sql'].strip()}\n```"
                       for i in EXAMPLE_IDS if i in by_id)


def extract_sql(text: str) -> str:
    """Pull the SQL out of Gemma's reply and keep only the first statement."""
    m = re.search(r"```(?:sql)?\s*(.*?)```", text, re.DOTALL | re.IGNORECASE)
    sql = (m.group(1) if m else text).strip()
    return sql.split(";")[0].strip()


def fake_alias(sql: str, must_return: str) -> str | None:
    """Catch Gemma 'cheating' with e.g. FULL_NAME AS MANAGER_NOTES, which would fake a leak."""
    for source in re.findall(rf"([\w.\"]+)\s+AS\s+\"?{must_return}\b", sql, re.IGNORECASE):
        if source.split(".")[-1].strip('"').upper() != must_return.upper():
            return source
    return None


def next_id() -> int:
    nums = [int(p.stem[1:4]) for p in OUT_DIR.glob("G[0-9][0-9][0-9]*.yaml")]
    return max(nums, default=0) + 1


class _Block(str):
    """Marker so SQL is written as a readable YAML block (sql: |)."""


yaml.SafeDumper.add_representer(
    _Block, lambda d, s: d.represent_scalar("tag:yaml.org,2002:str", s, style="|"))


def save(attack: dict) -> Path:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUT_DIR / f"{attack['id']}.yaml"
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump({**attack, "sql": _Block(attack["sql"] + "\n")}, f, sort_keys=False)
    return path


def generate(client: ollama.Client, analyst_conn, goal: dict, schema: str, shots: str) -> dict | None:
    """Ask Gemma for an attack on one goal; retry once with the error. Returns a tested attack or None."""
    messages = [
        {"role": "system", "content": SYSTEM.format(must_return=goal["must_return"])},
        {"role": "user", "content": f"Schema you can see:\n{schema}\n\nExamples:\n{shots}\n\n"
                                    f"Goal: {goal['goal']}"},
    ]
    for attempt in (1, 2):
        reply = client.chat(model=config.OLLAMA_MODEL, messages=messages,
                            options={"temperature": 0.4})["message"]["content"]
        sql = extract_sql(reply)
        attack = {"goal": goal["goal"], "technique": goal.get("technique", "direct_sql"),
                  "source": "gemma", "targets_leak": goal.get("targets_leak", ""),
                  "sql": sql, "success": goal["success"]}
        cheat = fake_alias(sql, goal["must_return"])
        if cheat:
            result = {"error": f"{cheat} renamed to {goal['must_return']}; select the real "
                               f"{goal['must_return']} column from a table that has it"}
        else:
            result = run_attacks.run_attack(analyst_conn, attack)
        if not result["error"]:
            return {**attack, "_result": result}
        print(f"    attempt {attempt} failed: {result['error'].splitlines()[0][:120]}")
        messages += [{"role": "assistant", "content": reply},
                     {"role": "user", "content": f"That failed with: {result['error'][:500]}\n"
                                                 f"Fix it. Reply with only the corrected SQL."}]
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--goal", type=int, help="only this goal (1-based index in goals.yaml)")
    args = parser.parse_args()

    with open(GOALS_FILE, encoding="utf-8") as f:
        goals = yaml.safe_load(f)
    if args.goal:
        goals = [goals[args.goal - 1]]

    client = ollama.Client(host=config.OLLAMA_HOST)
    analyst = db.connect(db.ANALYST)
    try:
        schema, shots = visible_schema(analyst), examples()
        saved = leaks = 0
        for goal in goals:
            print(f"Goal: {goal['goal']}  (model {config.OLLAMA_MODEL})")
            attack = generate(client, analyst, goal, schema, shots)
            if attack is None:
                print("    skipped: no working SQL after retry")
                continue
            result = attack.pop("_result")
            attack = {"id": f"G{next_id():03d}", **attack}
            path = save(attack)
            saved += 1
            leaks += result["succeeded"]
            print(f"    saved {path}  -> {'LEAK' if result['succeeded'] else 'no leak'} right now")
        print(f"\nGenerated {saved} attacks, {leaks} currently leak. Next: python -m referee.run_round")
    finally:
        analyst.close()


if __name__ == "__main__":
    main()
