# STATUS — update your own section only (pull first). Format: [time] done / doing / blocked

## Manav
- [ ] Enterprise trial + `sql/00_setup.sql` (sections A–E) + LH_BOT key + `.env` shared privately
- [ ] Public data listing + exact zip table posted in CONTRACTS §4
- [ ] `setup/generate_data.py`, `plant_leaks.py`, `reset.py`
- [ ] Defender: CoCo run + `defender/apply_fixes.py` fallback + pii-guardian validated
- [ ] `report/generate.py`

## Manas
- [x] Ollama + Gemma producing valid SQL (`gemma3:4b`, tested offline against CONTRACTS §3 schema)
- [x] `referee/run_attacks.py`, `run_legit.py`, `run_round.py` — live Round 1 on Snowflake: leaks 6/7 (A03 not configured), legit 10/10
- [x] `legit/queries.yaml` (10 queries) — base tables only, no names/SSNs; pass on a DuckDB mock with and without masking
- [ ] A03 re-identification — blocked: "Snowflake Public Data (Free)" not in the account yet (SHOW DATABASES), CONTRACTS §4 still TBD
- [x] `attacker/gemma_attacker.py` live: G001–G005 generated, 4 leak before fixes (G003 found name+diagnosis via PATIENT_DEMOGRAPHICS join)
- [ ] Stretch: `chatbot/`

## Reya
- [ ] Read README → AGENTS → PLAN → CONTRACTS → docs/BOUNCER.md; smoke tests pass
- [ ] Bouncer logging to `RESULTS.BOUNCER_LOG`
- [ ] `scoreboard/app.py` (big numbers, rounds, Rejected panel, Bouncer panel)
- [ ] Bouncer Gemma demo script + agent wiring + `skills-ref validate ./skills/bouncer`
- [ ] Demo rehearsal, backup video, MLH submission by 3:20

## Checkpoints
- [ ] 2:15 — Round 1 end to end + one Bouncer check on the scoreboard
- [ ] 2:50 — Full loop: leaks → 0, legit 10/10, Bouncer blocks a package (FEATURE FREEZE)
- [ ] 3:20 — Submitted
