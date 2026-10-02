# STATUS — update your own section only (pull first). Format: [time] done / doing / blocked

## Manav
- [x] Enterprise trial + `sql/00_setup.sql` + LH_BOT key-pair auth (`python -m leakhunter.db` OK). TODO: run section E (BOUNCER_LOG) in Snowsight; DM `.env` + key
- [ ] Public data listing + exact zip table posted in CONTRACTS §4
- [x] `setup/generate_data.py`, `plant_leaks.py`, `reset.py`, `verify.py` — live: verify planted + closed both ALL GOOD; leaks currently planted (--all) for the referee
- [x] `defender/apply_fixes.py` fallback works live; pii-guardian validated (skills-ref 0 errors)
- [ ] Defender: CoCo run + screenshots in `docs/coco/`
- [x] `report/generate.py` (tested on sample data; run after the re-check round: `python -m report.generate` → `report/audit_report.md`)

## Manas
- [x] Ollama + Gemma producing valid SQL (`gemma3:4b`, tested offline against CONTRACTS §3 schema)
- [x] `referee/run_attacks.py`, `run_legit.py`, `run_round.py` written + tested with a fake connection; live test waiting on `.env` from Manav
- [ ] A03 re-identification finalized against public table — blocked: needs CONTRACTS §4 table + columns
- [x] `attacker/gemma_attacker.py` written (goals now carry their success rule; rejects fake column aliases); live run waiting on `.env`
- [ ] Stretch: `chatbot/`
- [x] `legit/queries.yaml` Q04-Q10 filled in by Reya (Manas: review, they run through your `run_legit.py`)

## Reya
- [x] Connection smoke test passes (both roles); `.env` + key in place
- [x] `scoreboard/app.py` (big numbers, round history, leak log, fixes, Rejected panel, Change Firewall panel); verified against a stub
- [x] `firewall/` Change Firewall + Package Guard, `python -m firewall.selftest` passes offline; `pii-guardian` skill now submits changes through it (heads-up Manav)
- [x] Bouncer logging to `RESULTS.BOUNCER_LOG` (table created from sql/00_setup.sql section E; live rows verified)
- [x] Bouncer scoreboard panel (green/yellow/red chips + table)
- [x] `skills/bouncer/scripts/demo_gemma.py` (live Gemma or `--sample`; Ollama not installed on Reya's machine yet) + both skills validate
- [ ] Bouncer agent wiring (CoCo/Claude Code refusing a BLOCKed package) + screenshot into `docs/coco/`
- [x] Live check on Snowflake: round 2 = 6/7 leaks (A03 waits on public ZIP table), legit 10/10; firewall BLOCK/PASS/package-BLOCK all verified, no clone left behind
- [ ] Demo rehearsal, backup video, MLH submission by 3:20

## Checkpoints
- [ ] 2:15 — Round 1 end to end + one Bouncer check on the scoreboard
- [ ] 2:50 — Full loop: leaks → 0, legit 10/10, Bouncer blocks a package (FEATURE FREEZE)
- [ ] 3:20 — Submitted
