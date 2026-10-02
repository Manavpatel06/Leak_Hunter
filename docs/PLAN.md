# PLAN — LeakHunter build day

Times assume we start building at ~1:15. If we start later, keep the checkpoints and use the cut list.
**Hard deadline: submit on MLH by 3:20 PM** (official deadline 3:30). Expo 3:30–4:45.

## Ownership (equal thirds)

| Person | Owns | Folders |
|---|---|---|
| **Manav** | Snowflake foundation, synthetic data + planted leaks, public-data join, the defender (pii-guardian skill + CoCo fixes), audit report, repo | `sql/`, `setup/`, `defender/`, `skills/pii-guardian/`, `report/` |
| **Manas** | The attacker (attack library, Gemma generator, re-identification attack), the referee engine, legitimate analyst queries | `attacks/`, `attacker/`, `referee/`, `legit/`, `chatbot/` |
| **Reya** | **Bouncer** (second skill: blocks bad packages before AI agents install them), scoreboard (incl. Rejected + Bouncer panels), demo, backup video, MLH submission | `skills/bouncer/`, `scoreboard/`, `demo/`, `docs/DEMO.md`, `docs/BOUNCER.md` |

Shared (`leakhunter/`, `docs/CONTRACTS.md`, `AGENTS.md`): change only after a message in the group.

## Timeline

### Phase 0 — Foundation (1:15–1:35)
- **Manav:** Enterprise trial → run `sql/00_setup.sql` (all sections, incl. E for Bouncer) → service user key (CONTRACTS §10) → DM `.env` + key file → get "Snowflake Public Data (Free)" → confirm CoCo in Snowsight.
- **Manas:** Ollama + smallest Gemma writing a valid `SELECT` from a schema. Clone, `.env`, `python -m leakhunter.db`.
- **Reya:** read README → AGENTS → PLAN → CONTRACTS → `docs/BOUNCER.md` (10 min). Clone, `.env`, `python -m leakhunter.db`. Run `python skills/bouncer/scripts/check.py requests reqeusts` (works even before Snowflake is ready).

### Phase 1 — Build the pieces (1:35–2:15)
- **Manav:** `setup/generate_data.py`, `setup/plant_leaks.py`, `setup/reset.py`; find the public ZIP population table with CoCo and post its exact name (CONTRACTS §4).
- **Manas:** `referee/run_attacks.py`, `run_legit.py`, `run_round.py`; `legit/queries.yaml` to 10 queries; start `attacker/gemma_attacker.py`.
- **Reya:** Bouncer logging to `RESULTS.BOUNCER_LOG`; `scoreboard/app.py` first version (big numbers + round history).

### ✅ Checkpoint 1 — 2:15
Round 1 runs end to end: attacks execute as `LH_ANALYST`, scoreboard shows the leaks and 10/10 legit queries, and one Bouncer check appears on the scoreboard. **If the round doesn't run, everyone helps fix it before anything else.**

### Phase 2 — Close the loop (2:15–2:50)
- **Manav:** defender run: CoCo reads `RESULTS.LEAK_LOG` + `skills/pii-guardian`, applies fixes, logs to `RESULTS.FIXES`; `defender/apply_fixes.py` fallback; `report/generate.py`.
- **Manas:** finalize the re-identification attack (A03) on the public table; Gemma-generated attacks into `attacks/generated/`; rounds re-run cleanly.
- **Reya:** Bouncer demo script with Gemma + agent wiring (`docs/BOUNCER.md` tasks 3–4); scoreboard Rejected + Bouncer panels; `demo/judge_breaks.sql` tested with Manav.

### ✅ Checkpoint 2 — 2:50 · FEATURE FREEZE
Full loop: attack → fix → re-check shows leaks → 0 with legit 10/10, and the Bouncer demo blocks at least one package. After this, only fixes and rehearsal.

### Phase 3 — Ship (2:50–3:20)
- 2:50–3:00 Everyone: run `docs/DEMO.md` twice, including the judge break and the Bouncer beat.
- 3:00–3:10 Reya: record backup video. Manav: CoCo screenshots into `docs/coco/`. Manas: README numbers from the real run.
- 3:10–3:20 Reya: submit on MLH (link in CONTRACTS §12). Make repo public. **Submitted by 3:20.**

## The "Rejected" panel (owner: Reya)
Borrowed from StressTrace's Signal Graveyard. The scoreboard lists every attack that **failed**, with the reason (masked value returned, permission denied, invalid SQL). Reads `RESULTS.ATTACK_RUNS` where `SUCCEEDED = FALSE`; no new tables.

## Stretch (only after Checkpoint 2 passes early, or group OK)
1. Chatbot attack (Manas): plain-English questions to a data chatbot running as `LH_ANALYST` (CONTRACTS §6).
2. Compliance tags in the report (Manav).
3. Random leak planting in the live demo (Manav).

## Cut list if behind (cut in this order)
1. Gemma-generated attacks → hand-written library only.
2. Bouncer agent wiring → show `check.py` in the terminal instead.
3. Streamlit polish → plain tables + big numbers.
4. Plant 3 leaks instead of 6.
5. CoCo applies fixes by hand in Snowsight while we narrate; fixes still logged.
Never cut: the re-identification attack (our free-dataset requirement), the legit-queries check, and the Bouncer `check.py` blocking an invented package (already built).

## Communication
- Group chat for anything that changes a contract or blocks someone.
- Blocked for more than 10 minutes → post in the group.
- At each checkpoint: 2-minute sync, everyone says done / blocked / next.
