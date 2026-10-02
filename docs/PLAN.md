# PLAN — LeakHunter build day

Times assume we start building at ~1:05. If we start later, keep the checkpoints and use the cut list.
**Hard deadline: submit on MLH by 3:20 PM** (official deadline 3:30). Expo 3:30–4:45.

## Ownership (equal thirds)

| Person | Owns | Folders |
|---|---|---|
| **Manav** | Snowflake foundation, synthetic data + planted leaks, public-data join, the defender (skill + CoCo fixes), repo | `sql/`, `setup/`, `defender/`, `skills/pii-guardian/` |
| **Manas** | The attacker (attack library, Gemma generator, re-identification attack), the referee engine | `attacks/`, `attacker/`, `referee/`, `chatbot/` |
| **Reya** (from 1:00) | Legitimate analyst queries, scoreboard, audit report, demo, README polish, MLH submission | `legit/`, `scoreboard/`, `report/`, `demo/`, `docs/DEMO.md` |

Shared (`leakhunter/`, `docs/CONTRACTS.md`, `AGENTS.md`): change only after a message in the group.

## Timeline

### Phase 0 — Foundation (1:05–1:30)
- **Manav:** Snowflake account is **Enterprise edition** (masking needs it) → run `sql/00_setup.sql` → create service user + key (steps in `docs/CONTRACTS.md` §7) → send `.env` values and key file privately → get "Snowflake Public Data (Free)" from Marketplace → confirm CoCo opens in Snowsight. Push repo, add collaborators.
- **Manas:** install Ollama, pull smallest Gemma, confirm it writes a valid `SELECT` given a schema. Clone repo, run `python -m leakhunter.db`.
- **Reya (on arrival):** read README → AGENTS → PLAN → CONTRACTS (10 min), clone, `.env`, run `python -m leakhunter.db`.

### Phase 1 — Build the pieces (1:30–2:15)
- **Manav:** `setup/generate_data.py` (tables in CONTRACTS §3), `setup/plant_leaks.py` (leaks L1–L6, `--all` or `--random N --seed S`), find the public zip-population table with CoCo and record its exact name in CONTRACTS §4 + group chat.
- **Manas:** `referee/run_attacks.py` (runs every YAML in `attacks/`, logs to `RESULTS.ATTACK_RUNS`), hand-write 6 library attacks (one per leak L1–L6), start `attacker/gemma_attacker.py`.
- **Reya:** `legit/queries.yaml` (10 queries an analyst legitimately needs), `referee/run_legit.py` hook agreed with Manas (Manas owns the runner, Reya owns the queries), `scoreboard/app.py` reading `RESULTS.SCOREBOARD`.

### ✅ Checkpoint 1 — 2:15
Round 1 runs end to end: attacks execute as `LH_ANALYST`, the scoreboard shows ~6 leaks and 10/10 legit queries. **If not, everyone helps fix this before anything else.**

### Phase 2 — Close the loop (2:15–2:50)
- **Manav:** defender run: CoCo reads `RESULTS.LEAK_LOG` + `skills/pii-guardian`, applies fixes, logs each to `RESULTS.FIXES`. Test the re-check: leaks → 0, legit still 10/10.
- **Manas:** re-identification attack using the public table (CONTRACTS §5), Gemma-generated attacks saved to `attacks/generated/`, re-run engine handles new rounds.
- **Reya:** scoreboard polish (big numbers, round timeline, latest fix SQL, **Rejected panel**), `report/generate.py` audit report, `demo/judge_breaks.sql` tested with Manav.

### ✅ Checkpoint 2 — 2:50 · FEATURE FREEZE
Full loop works: attack → fix → re-check shows leaks 6 → 0 with legit 10/10. After this, no new features, only fixes and rehearsal.

### Phase 3 — Ship (2:50–3:20)
- 2:50–3:00 Everyone: run `docs/DEMO.md` start to finish twice, including the judge break.
- 3:00–3:10 Reya: record backup screen video (whole demo). Manav: CoCo screenshots into `docs/coco/`. Manas: repo cleanup, final README numbers.
- 3:10–3:20 Reya: submit on MLH (link in CONTRACTS §8). Make repo public. **Submitted by 3:20.**

## The "Rejected" panel (owner: Reya)
Borrowed from StressTrace's Signal Graveyard. The scoreboard lists every attack that **failed**, with the reason (blocked by masking, permission denied, invalid SQL). No new tables: it reads `RESULTS.ATTACK_RUNS` where `SUCCEEDED = FALSE`. On stage: "Here's everything the attacker tried that didn't work, and why. We show what we refused to count as a leak."

## Stretch (only after Checkpoint 2 passes early, or group OK)
1. Chatbot attack (Manas): plain-English questions to a data chatbot running as `LH_ANALYST` (CONTRACTS §6).
2. Compliance tags in the report (Reya).
3. Random leak planting in the live demo (Manav).

## Cut list if behind (cut in this order)
1. Gemma-generated attacks → demo the hand-written library only (Gemma still generates one live).
2. Streamlit polish → plain table + two big numbers.
3. Plant 3 leaks instead of 6.
4. CoCo applies fixes by hand in Snowsight while we narrate; fixes still logged.
Never cut: the re-identification attack (it's our free-dataset requirement) and the legit-queries check.

## Communication
- Group chat for anything that changes a contract or blocks someone.
- Blocked for more than 10 minutes → post in the group.
- At each checkpoint: 2-minute sync, everyone says done / blocked / next.
