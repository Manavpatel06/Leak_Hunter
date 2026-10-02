# AGENTS.md — shared context for every AI coding tool on this repo

You are helping one member of a 3-person hackathon team build **LeakHunter** in about 3 hours.
Three people use three different AI tools on this repo at the same time. Your job is to keep
your human's work compatible with everyone else's. Read this whole file before writing code.

## What we are building (one paragraph)
An open-source agent skill + scripts that find and fix data leaks in a Snowflake warehouse.
An open-weight attacker model (Gemma via Ollama) runs SQL attacks as a low-privilege role.
A defender (Snowflake CoCo using our `skills/pii-guardian` skill) applies Snowflake-native fixes.
A referee re-runs every attack plus legitimate analyst queries, and a Streamlit scoreboard shows
"leaks remaining" and "legitimate queries still working". Full pitch: `docs/IDEA.md`.

## Non-negotiable rules
1. **`docs/CONTRACTS.md` is the source of truth.** Use its exact database, schema, role, table,
   column, and file-format names. Never invent or rename them. If a contract seems wrong, stop and
   tell your human to raise it in the group chat; do not "fix" it silently.
2. **Only edit files in your human's owned folders** (ownership table in `docs/PLAN.md`).
   Shared files (`docs/CONTRACTS.md`, `leakhunter/`, `AGENTS.md`, `requirements.txt`) change only
   after the group agrees. `requirements.txt` is append-only.
3. **Use the shared helpers in `leakhunter/db.py`** for every Snowflake connection and every write
   to `LEAKHUNTER.RESULTS`. Do not write your own connection code.
4. **Attacks always run as role `LH_ANALYST` with secondary roles NONE** (`db.connect` does this).
   Logging and fixes run as `LH_ADMIN`. Getting this wrong makes every attack "succeed" falsely.
5. **Secrets never enter git.** No passwords, keys, account identifiers, or `.env` in commits.
   `.gitignore` already blocks `.env` and `*.p8`.
6. **Synthetic data only.** Fake SSNs start with 9 (900–999), which are never issued as real SSNs.
7. **Simple beats clever.** Python 3.11, plain scripts, no frameworks beyond `requirements.txt`.
   Every script must run from the repo root as `python -m <package>.<module>`.
8. **Small commits, pull first.** `git pull --rebase` before every push. Commit message format:
   `[area] what changed`, e.g. `[attacker] add re-identification attack`.
9. **Update `STATUS.md`** (your human's section only) when a task finishes or gets blocked.
10. **Ask before scope creep.** Stretch items in `docs/PLAN.md` are only started after the 2:50
    checkpoint passes, or with the group's OK.

## Tech choices (fixed — do not swap)
- Snowflake (trial account, Enterprise edition), Python `snowflake-connector-python`
- Attacker model: Gemma via Ollama, model name from env `OLLAMA_MODEL`
- Defender: Snowflake CoCo (Cortex Code) + `skills/pii-guardian` (Agent Skill Open Standard)
- UI: Streamlit, run locally
- Config: `.env` loaded by `leakhunter/config.py`

## Definition of done for any task
Runs from a clean clone with `pip install -r requirements.txt`, uses contract names exactly,
writes results through `leakhunter/db.py`, and is noted in `STATUS.md`.
