# referee/ — owner: Manas

## Tasks
1. `run_attacks.py` — load every YAML in `attacks/library/` and `attacks/generated/`, substitute `{PUBLIC_ZIP_TABLE}` from config, run each as `LH_ANALYST` via `db.connect(ANALYST)`, judge it with its `success` rule, log with `db.log_attack_run`. Supports `direct_sql`, `join`, `reidentification`, `role_escalation`, `sweep` (and `chatbot` if the stretch lands).
2. `run_legit.py` — run every query in `legit/queries.yaml` as `LH_ANALYST`, log with `db.log_legit_run`.
3. `run_round.py` — `round = db.next_round(admin)`, then attacks + legit for that round, then print the scoreboard row.

## Done when
`python -m referee.run_round` prints e.g. `Round 1: leaks 6/7, legit 10/10`, and RESULTS tables fill.
