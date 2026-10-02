# STATUS — update your own section only (pull first). Format: [time] done / doing / blocked

## Manav
- [x] Enterprise trial + `sql/00_setup.sql` + LH_BOT key-pair auth (`python -m leakhunter.db` OK). TODO: run section E (BOUNCER_LOG) in Snowsight; DM `.env` + key
- [x] Public data: `DATA.ZIP_POPULATION` from ACS (CONTRACTS §4, `sql/02_zip_population.sql`); re-identification live = 137 of 2,000 patients
- [x] `setup/generate_data.py`, `plant_leaks.py`, `reset.py`, `verify.py` — live: verify planted + closed both ALL GOOD; leaks currently planted (--all) for the referee
- [x] `defender/apply_fixes.py` fallback works live; pii-guardian validated (skills-ref 0 errors)
- [ ] CoCo BLOCKED: trial accounts need a card for AI features -> defender = `apply_fixes.py` (group to confirm)
- [x] `report/generate.py` (tested on sample data; run after the re-check round: `python -m report.generate` → `report/audit_report.md`)

## Manas
- [x] Ollama + Gemma producing valid SQL (`gemma3:4b`)
- [x] `referee/run_attacks.py`, `run_legit.py`, `run_round.py` — live Round 1 on Snowflake: leaks 6/7, legit 10/10
- [x] A03 re-identification on `DATA.ZIP_POPULATION` (CONTRACTS §4): live 137 re-identifiable patients with L3 planted, 0 with ZIP masked; `setup.verify` now runs it (uses `BETWEEN 0 AND 4999` because verify skips SQL containing `<`)
- [x] `attacker/gemma_attacker.py` live: G001–G005 in `attacks/generated/`, 4 leak before fixes (G003 links name+diagnosis by joining PATIENT_DEMOGRAPHICS back to PATIENTS); goals can require several columns
- [x] `legit/queries.yaml` Q04-Q10 (Reya's version kept, reviewed: aggregates only, survive masking)
- [ ] Stretch: `chatbot/`

## Reya
- [x] Connection smoke test passes (both roles); `.env` + key in place
- [x] `scoreboard/app.py` (big numbers, round history, leak log, fixes, Rejected panel, Change Firewall panel); verified against a stub
- [x] `firewall/` Change Firewall + Package Guard, `python -m firewall.selftest` passes offline; `pii-guardian` skill now submits changes through it (heads-up Manav)
- [x] Bouncer logging to `RESULTS.BOUNCER_LOG` (table created from sql/00_setup.sql section E; live rows verified)
- [x] Bouncer scoreboard panel (green/yellow/red chips + table)
- [x] `skills/bouncer/scripts/demo_gemma.py` (live Gemma or `--sample`; Ollama not installed on Reya's machine yet) + both skills validate
- [x] Bouncer is wired into the firewall's Package Guard (live PyPI checks, logged to BOUNCER_LOG); `python demo/run_demo.py doctor|agent|round|scoreboard|all` runs everything; firewall PASS ~13 s, bad package blocked ~4 s
- [x] Interactive dashboard `docs/showcase.html` (built from live data by `demo/build_showcase.py`), `docs/OVERVIEW.md`, README updated; live A03 now runs (public ZIP table set locally in .env)
- [ ] Bouncer agent wiring (CoCo or another agent refusing a BLOCKed package) + screenshot into `docs/coco/`
- [x] Live check on Snowflake: round 2 = 6/7 leaks (A03 waits on public ZIP table), legit 10/10; firewall BLOCK/PASS/package-BLOCK all verified, no clone left behind
- [ ] Demo rehearsal, backup video, MLH submission by 3:20

## Checkpoints
- [ ] 2:15 — Round 1 end to end + one Bouncer check on the scoreboard
- [ ] 2:50 — Full loop: leaks → 0, legit 10/10, Bouncer blocks a package (FEATURE FREEZE)
- [ ] 3:20 — Submitted
