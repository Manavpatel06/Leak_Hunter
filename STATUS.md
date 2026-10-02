# STATUS — update your own section only (pull first). Format: [time] done / doing / blocked

## Manav
- [ ] Enterprise trial + `sql/00_setup.sql` (sections A–E) + LH_BOT key + `.env` shared privately
- [ ] Public data listing + exact zip table posted in CONTRACTS §4
- [ ] `setup/generate_data.py`, `plant_leaks.py`, `reset.py`
- [ ] Defender: CoCo run + `defender/apply_fixes.py` fallback + pii-guardian validated
- [ ] `report/generate.py`

## Manas
- [x] Ollama + Gemma producing valid SQL (`gemma3:4b`, tested offline against CONTRACTS §3 schema)
- [x] `referee/run_attacks.py`, `run_legit.py`, `run_round.py` written + tested with a fake connection; live test waiting on `.env` from Manav
- [ ] `legit/queries.yaml` (10 queries)
- [ ] A03 re-identification finalized against public table — blocked: needs CONTRACTS §4 table + columns
- [x] `attacker/gemma_attacker.py` written (goals now carry their success rule; rejects fake column aliases); live run waiting on `.env`
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
