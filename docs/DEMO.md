# DEMO — expo script (~3.5–4 min). Owner: Reya. Rehearse twice before 3:00.

Before judges arrive: `python -m setup.reset && python -m setup.plant_leaks --all`, scoreboard open full-screen, Snowsight + CoCo open in another tab, terminal ready.

| Time | Who | Beat |
|---|---|---|
| 20 s | Manav | **Hook:** "This patient data is 'anonymized.' Who here thinks it's safe?" |
| 20 s | Reya | **Warehouse:** scoreboard says no rounds yet. "Synthetic hospital and HR data, next to free public census data." |
| 45 s | Manas | **Attack:** `python -m referee.run_round`. Narrate: SSNs, salaries by name, and the re-identification join with public data. Scoreboard turns red: N leaks, legit 10/10. |
| 45 s | Manav | **Defend:** CoCo with the pii-guardian skill reads the leak log and applies fixes. Show one masking policy it wrote. |
| 30 s | Manas | **Re-check:** `python -m referee.run_round`. Leaks 0, legit still 10/10. "Fixed without breaking anyone's job." |
| 15 s | Reya | **Rejected panel:** "Everything the attacker tried that failed, and why. We don't count what we can't prove." |
| 30 s | Judge | **Judge's turn:** judge runs one line from `demo/judge_breaks.sql`. Round → caught → fix → round → 0. |
| 15 s | Reya | **Close:** "The skill is open source. Any company can run this on its own warehouse today." Show repo. |

Backup: if anything fails live, play the recorded video (recorded 3:00–3:10) and keep narrating.
Likely judge questions: "Isn't this just Snowflake's data classification?" → classification finds where data is; we prove it's reachable and prove the fix. "You planted the leaks?" → "Then you plant one."
