# DEMO — expo script (~4 min; trim the Rejected beat first if over). Owner: Reya. Rehearse twice before 3:00.

Before judges arrive: `python demo/run_demo.py doctor` (READY), then `python -m setup.reset && python -m setup.plant_leaks --all`, scoreboard open full-screen, terminal ready, `report/dashboard.html` from the last full run open in a second tab.

**CoCo is not available:** Snowflake trial accounts only enable AI features (CoCo, AI_COMPLETE) after a credit card is added, and we run at $0. The defender is `python -m defender.apply_fixes`, which applies the open pii-guardian skill's playbook. If asked: "The skill is an open Agent Skill: CoCo, Claude Code or any agent can load it; on a paid account CoCo runs the same playbook."

**Full proof in one command (rehearsal / backup):** `python demo/run_demo.py loop` → reset, plant, round, defend, re-check, audit report, dashboard.

| Time | Who | Beat |
|---|---|---|
| 20 s | Manav | **Hook:** "This patient data is 'anonymized.' Who here thinks it's safe?" |
| 20 s | Reya | **Warehouse:** scoreboard says no rounds yet. "Synthetic hospital and HR data, next to free public census data." |
| 45 s | Manas | **Attack:** `python -m referee.run_round`. Narrate: SSNs, salaries by name, and the re-identification join with public data. Scoreboard turns red: N leaks, legit 10/10. |
| 45 s | Manav | **Defend:** `python -m defender.apply_fixes`. It reads the leak log and applies the pii-guardian playbook: masks on SSN / names / ZIP / birth date, revokes the HR role, drops the forgotten export. Read one line aloud, e.g. `SET MASKING POLICY ... MASK_SSN`. Never runs the attacker's SQL. |
| 30 s | Manas | **Re-check:** `python -m referee.run_round`. Leaks 0, legit still 10/10. "Fixed without breaking anyone's job." |
| 15 s | Reya | **Rejected panel:** "Everything the attacker tried that failed, and why. We don't count what we can't prove." |
| 30 s | Reya | **Bouncer:** "Leaks don't only come from permissions; they come from the code your AI installs." Run the Gemma demo; any invented package is blocked on the scoreboard. |
| 30 s | Judge | **Judge's turn:** judge runs one line from `demo/judge_breaks.sql` (or `python demo/run_demo.py judge` does option 1 + round → fix → round). Caught → fixed → 0. |
| 15 s | Reya | **Close:** open `report/dashboard.html`: leaks N → 0, legit 10/10, 137 patients re-identifiable from free Census data before the fix. "The skills are open source. Any company can run this on its own warehouse today." Show repo. |

## Change Firewall beat (optional ~90 s, after the Re-check beat; this is the "agents are coming" answer)

Setup once: `python demo/run_demo.py doctor` must say READY and `python -m firewall.selftest` ALL PASSED. Have
`firewall/examples/` open in an editor. **Whole beat in one command:** `python demo/run_demo.py agent` (add `--merge --cleanup`
to really apply the PASS and remove the demo view; add `--sample` if Ollama is not running).

| Time | Beat |
|---|---|
| 15 s | **An AI agent asks:** "Build an analytics view of patients by ZIP and birth date." Say: "Agents like CoCo now get write access. What stops one creating a view that leaks patients?" |
| 25 s | **Intercept:** the skill makes the agent submit it: `python -m firewall.leakcheck --sql-file firewall/examples/bad_patient_analytics.sql`. Narrate the steps: clone, apply to the clone only, attack as the analyst. Output: `BLOCK`, with the canary patient re-identified by ZIP + birth date. "Like a rejected pull request, with the attack attached." |
| 25 s | **Rewrite:** the agent reads `feedback.reasons`, writes the `good_patient_analytics.sql` version (3-digit ZIP, decade, groups of 5+) and resubmits with `--merge`. `PASS`, merged. |
| 15 s | **Record:** scoreboard "Change Firewall" panel shows BLOCKED then MERGED. "Compliance gets an audit trail for every agent change." |
| 10 s | **Package Guard:** `python -m firewall.package_guard --sql-file firewall/examples/bad_package.sql` blocks a typosquatted package and an egress integration. |

Say honestly if asked: "In the demo the skill makes the agent use the gate; production enforcement needs a Snowflake-side hook, that's the roadmap. A PASS means not breakable by our attacks, not provably safe."

Backup: if anything fails live, play the recorded video (recorded 3:00–3:10) and keep narrating.
Likely judge questions: "Isn't this just Snowflake's data classification?" → classification finds where data is; we prove it's reachable and prove the fix. "You planted the leaks?" → "Then you plant one."
