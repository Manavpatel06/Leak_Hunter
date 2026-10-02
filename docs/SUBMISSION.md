# MLH submission text (paste into the form). Owner: Reya. Fill the [brackets] from the final run.

**Name:** LeakHunter

**Tagline:** Continuous leak testing for data platforms: attack your warehouse like an insider, fix what's proven, prove the fix holds without breaking anyone's work.

**Tracks:** Best Use of Snowflake · Best Open-Source AI Project

## Inspiration
Most data leaks are not hacks. They are a column nobody masked, a role granted "temporarily", a forgotten export, or
"anonymized" data that is not anonymous: ZIP code + birth date + sex singles out most people. Audits catch this once a
year. AI agents with warehouse access make it worse.

## What it does
- **Attack:** an open-weight model (Gemma via Ollama) plus a hand-written attack library run SQL as a low-privilege analyst
  role: read SSNs, salaries by name, private HR reviews, forgotten exports, and a **re-identification attack that joins our
  "anonymized" patient view with free US Census data from Snowflake Marketplace**. Result: 137 of 2,000 synthetic
  patients singled out.
- **Defend:** the open `pii-guardian` Agent Skill maps every proven leak to the smallest Snowflake-native fix (masking
  policies, revoked role grants, dropping scratch copies) and logs it.
- **Prove:** a referee re-runs every attack *and* 10 legitimate analyst queries. Leaks 11 → 0, legitimate queries 10/10.
- **Judge's turn:** a judge opens a new hole live (e.g. a "quick export"); the SSN sweep catches it, it is fixed, re-proven.
- **Agents at the door:** `Bouncer` (second Agent Skill) blocks invented or look-alike packages before an AI agent installs
  them; the **Change Firewall** tests any agent-proposed change on a zero-copy clone, attacks the clone, and only merges on PASS.
- **Audit report + dashboard:** one-page audit report (each leak tagged to HIPAA / GDPR), and a static results dashboard.

## How we built it
Snowflake (Enterprise trial): roles, masking policies, zero-copy clones, Marketplace "Snowflake Public Data
(Free)" (ACS population by ZIP). Python + snowflake-connector (key-pair auth), Gemma 3 via Ollama, Streamlit scoreboard,
two Agent Skills (open standard, validated with skills-ref). All data synthetic (SSNs 9XX, never issued).

## Challenges
Snowflake's AI features (Cortex Code / CoCo) need a payment method on trial accounts, and we built at $0, so the defender
runs the skill's playbook as a script; any agent (CoCo on a paid account, Claude Code, Gemma) can load the same skill.
Making attacks honest: every attack runs as the analyst with secondary roles off, otherwise everything "succeeds".

## What's next
LeakHunter is meant to plug into any data provider, not just this demo: connect two roles, schedule rounds after every
schema change or grant, and keep the audit trail for compliance. Next: adapters for other warehouses (the attack / fix /
prove loop and the YAML attack + legit-query formats are warehouse-neutral), Snowflake-side enforcement for the Change
Firewall, and maintainer-history checks for Bouncer.

**Repo:** https://github.com/Manavpatel06/Leak_Hunter (MIT)
