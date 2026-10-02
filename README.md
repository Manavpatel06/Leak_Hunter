# LeakHunter

**One AI attacks your Snowflake warehouse, another fixes every leak, and a referee proves the fixes hold without breaking anyone's legitimate work.**

sunhacks Hack Day (MLH Hacktoberfest), Oct 2, 2026 · Team: Manav, Manas, Reya
Tracks: Best Use of Snowflake · Best Open-Source AI Project · License: MIT

---

## Teammates: start here (read in this order, ~10 min)

1. `AGENTS.md` — the rules for us **and our AI coding tools**. Point your AI tool at it first.
2. `docs/PLAN.md` — timeline, who owns what, checkpoints, cut list.
3. `docs/CONTRACTS.md` — the shared names, tables, and file formats. **This is the source of truth.**
4. `STATUS.md` — what's done, what's blocked. Update your own section.
5. Your own area's folder (see the ownership table in `docs/PLAN.md`).

Background reading: `docs/IDEA.md` (the pitch), `docs/DEMO.md` (the expo script), `docs/BOUNCER.md` (the second skill).

## Quick start

```bash
git clone https://github.com/Manavpatel06/Leak_Hunter.git && cd Leak_Hunter
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env        # fill in; Manav sends secrets privately, never in the repo
python -m leakhunter.db     # connection smoke test: prints current role + warehouse
```

## How it works

1. **Setup** — synthetic hospital + HR warehouse with randomly planted weaknesses, next to Snowflake's free public zip-code population data.
2. **Attack** — an open-weight model (Gemma via Ollama) with a low-privilege role tries to steal SSNs, salaries-by-name, and re-identify "anonymized" patients by joining with public data.
3. **Fix** — CoCo, using our open-standard `pii-guardian` skill, applies Snowflake-native fixes (masking, row access, revoked grants).
4. **Referee** — re-runs every attack *and* a set of legitimate analyst queries. Scoreboard: leaks remaining vs. legitimate queries still working.
5. **Report** — plain-English audit summary, each leak tagged to the rule it breaks.
6. **Bouncer** — a second skill that checks every Python package *before* an AI agent installs it, blocking packages the AI invented, look-alikes of popular packages, and brand-new ones. Leaks don't only come from permissions; they come from the code your AI installs.

## Repo map

| Path | What | Owner |
|---|---|---|
| `sql/`, `setup/` | Snowflake objects, synthetic data, leak planting | Manav |
| `defender/`, `skills/pii-guardian/` | The fix skill + defender run | Manav |
| `attacks/`, `attacker/`, `referee/`, `chatbot/` | Attack library, Gemma attacker, re-run engine | Manas |
| `report/` | Audit report | Manav |
| `legit/` | Legitimate analyst queries | Manas |
| `skills/bouncer/`, `scoreboard/`, `demo/` | Bouncer skill, Streamlit scoreboard, demo | Reya |
| `leakhunter/` | Shared config + DB helpers (change only after telling the group) | shared |

All data is synthetic. No real personal data is used anywhere.
