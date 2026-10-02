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
- [ ] A03 re-identification finalized against public table — blocked: needs CONTRACTS §4 table + columns
- [x] `attacker/gemma_attacker.py` written (goals now carry their success rule; rejects fake column aliases); live run waiting on `.env`
- [ ] Stretch: `chatbot/`
- [x] `legit/queries.yaml` Q04-Q10 filled in by Reya (Manas: review, they run through your `run_legit.py`)

## Reya
- [x] Connection smoke test passes (both roles); `.env` + key in place
- [x] `scoreboard/app.py` (big numbers, round history, leak log, fixes, Rejected panel, Change Firewall panel); verified against a stub
- [x] `firewall/` Change Firewall + Package Guard, `python -m firewall.selftest` passes offline; `pii-guardian` skill now submits changes through it (heads-up Manav)
- [x] `report/generate.py` written (Manav: it is on your list too, take whichever you prefer)
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
