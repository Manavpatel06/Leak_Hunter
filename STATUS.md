# STATUS — update your own section only (pull first). Format: [time] done / doing / blocked

## Manav
- [x] Enterprise trial + `sql/00_setup.sql` + LH_BOT key-pair auth (`python -m leakhunter.db` OK). TODO: run section E (BOUNCER_LOG) in Snowsight; DM `.env` + key
- [ ] Public data listing + exact zip table posted in CONTRACTS §4
- [x] `setup/generate_data.py`, `plant_leaks.py`, `reset.py`, `verify.py` — live: verify planted + closed both ALL GOOD; leaks currently planted (--all) for the referee
- [x] `defender/apply_fixes.py` fallback works live; pii-guardian validated (skills-ref 0 errors)
- [ ] Defender: CoCo run + screenshots in `docs/coco/`
- [x] `report/generate.py` (tested on sample data; run after the re-check round: `python -m report.generate` → `report/audit_report.md`)

## Manas
- [ ] Ollama + Gemma producing valid SQL
- [ ] `referee/run_attacks.py`, `run_legit.py`, `run_round.py`
- [ ] `legit/queries.yaml` (10 queries)
- [ ] A03 re-identification finalized against public table
- [ ] `attacker/gemma_attacker.py` (generated attacks)
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
