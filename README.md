# LeakHunter

**One AI attacks your Snowflake warehouse, another fixes every leak, and a referee proves the fixes hold without breaking anyone's legitimate work.**

sunhacks Hack Day (MLH Hacktoberfest), Oct 2, 2026 · Team: Manav, Manas, **Reya Attri**
Tracks: Best Use of Snowflake · Best Open-Source AI Project · License: MIT

> **See it first:** open [`report/dashboard.html`](report/dashboard.html) in any browser: the results of the last full run, built from live warehouse data.
> For the full write-up (problem, design, results, limits), read [`docs/OVERVIEW.md`](docs/OVERVIEW.md).

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
python demo/run_demo.py doctor   # full preflight: env, key, both roles, tables, Ollama, PyPI
```

Run the demo (all from the repo root):

| Command | What it does |
|---|---|
| `python demo/run_demo.py round` | One referee round: every attack and every legitimate query |
| `python demo/run_demo.py agent` | The AI-agent story: Bouncer vets packages, the Change Firewall BLOCKs a leaky view, then PASSes the rewrite |
| `python demo/run_demo.py scoreboard` | Live Streamlit scoreboard (leaks, legit queries, Rejected, Bouncer, Change Firewall panels) |
| `python demo/run_demo.py dashboard` | Rebuild `report/dashboard.html` + `report/audit_report.md` from live data |
| `python -m firewall.selftest` | Offline proof the firewall logic works (no Snowflake needed) |

## How it works

1. **Setup** — synthetic hospital + HR warehouse with randomly planted weaknesses, next to Snowflake's free public zip-code population data.
2. **Attack** — an open-weight model (Gemma via Ollama) with a low-privilege role tries to steal SSNs, salaries-by-name, and re-identify "anonymized" patients by joining with public data.
3. **Fix** — the defender applies our open-standard `pii-guardian` skill's playbook: Snowflake-native fixes (masking, revoked grants, dropped copies). Any agent that supports Agent Skills can run the same playbook.
4. **Referee** — re-runs every attack *and* a set of legitimate analyst queries. Scoreboard: leaks remaining vs. legitimate queries still working.
5. **Report** — plain-English audit summary, each leak tagged to the rule it breaks.
6. **Bouncer** — a second skill that checks every Python package *before* an AI agent installs it, blocking packages the AI invented, look-alikes of popular packages, and brand-new ones. Leaks don't only come from permissions; they come from the code your AI installs.
7. **Change Firewall** — every change an AI agent wants to make to the warehouse is applied to a zero-copy clone first, attacked as the analyst (library attacks, a canary patient, re-identification and small-group probes), and merged to production only if nothing leaks. A BLOCK returns machine-readable feedback so the agent can rewrite and resubmit; every attempt is saved in `RESULTS.CHANGE_AUDIT`. Package Guard inside it asks Bouncer about any package the change would use. A PASS means "not breakable by these attacks", not "provably safe" (details and limits in `firewall/README.md`).

## Repo map

| Path | What | Owner |
|---|---|---|
| `sql/`, `setup/` | Snowflake objects, synthetic data, leak planting | Manav |
| `defender/`, `skills/pii-guardian/` | The fix skill + defender run | Manav |
| `attacks/`, `attacker/`, `referee/`, `chatbot/` | Attack library, Gemma attacker, re-run engine | Manas |
| `report/` | Audit report | Manav |
| `legit/` | Legitimate analyst queries | Manas |
| `skills/bouncer/`, `scoreboard/`, `demo/` | Bouncer skill, Streamlit scoreboard, demo runner, interactive dashboard | Reya |
| `firewall/` | Change Firewall + Package Guard (clone, attack, merge, audit) | Reya |
| `leakhunter/` | Shared config + DB helpers (change only after telling the group) | shared |

## Credits

Built at sunhacks Hack Day by **Reya Attri** (Bouncer, Change Firewall + Package Guard, scoreboard, demo runner, interactive dashboard, docs), **Manav** (Snowflake foundation, synthetic data and planted leaks, defender, audit report) and **Manas** (attack library, Gemma attacker, referee, legitimate queries).

All data is synthetic. No real personal data is used anywhere.
