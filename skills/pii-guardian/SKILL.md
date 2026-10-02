---
name: pii-guardian
description: Fixes confirmed data leaks in a Snowflake warehouse using Snowflake-native controls (masking policies, row access policies, revoked grants) while keeping legitimate analyst queries working. Use when given a leak log of successful attacks against sensitive data such as SSNs, names, salaries, or re-identifiable demographics.
license: MIT
compatibility: Requires a Snowflake account (Enterprise edition for masking and row access policies) and a role that owns the affected tables and policies.
metadata:
  project: LeakHunter
  version: "0.1"
---

# pii-guardian

You are the defender. An attacker running as a low-privilege role has proven some leaks.
Your job: close every proven leak with the smallest Snowflake-native change, log each fix,
and never break the legitimate analyst workload.

## Inputs
1. The leak log: `SELECT * FROM LEAKHUNTER.RESULTS.LEAK_LOG;` (successful attacks in the latest round).
2. The fix playbook: [references/fix-playbook.md](references/fix-playbook.md).
3. Legitimate queries that must keep working: `legit/queries.yaml` in the repo.

## Procedure
1. Read the leak log. For each row, note `ATTACK_ID`, `TECHNIQUE`, `SQL_TEXT`, and `EVIDENCE`.
2. Identify the root cause: an unprotected column, an over-broad role grant, a readable copy, or a view that joins identifiers to sensitive data.
3. Pick the fix from the playbook. Prefer, in order:
   1. **Mask the identifier, not the measure** (mask `FULL_NAME`, keep `SALARY` visible) so aggregates still work.
   2. **Mask at the base table column**: policies follow the column into every view.
   3. **Revoke** an over-broad grant or role inheritance.
   4. **Drop** only tables in `LEAKHUNTER.SCRATCH`.
4. Apply the fix as role `LH_ADMIN`.
5. Log every fix in the same round as the leak:
   ```sql
   INSERT INTO LEAKHUNTER.RESULTS.FIXES (FIX_ID, ROUND_NO, ATTACK_ID, FIX_TYPE, SQL_APPLIED, RATIONALE, APPLIED_BY)
   SELECT UUID_STRING(), (SELECT MAX(ROUND_NO) FROM LEAKHUNTER.RESULTS.ATTACK_RUNS),
          '<ATTACK_ID>', '<masking|row_access|revoke|drop_scratch|secure_view>',
          '<exact SQL you ran>', '<one sentence why>', 'coco';
   ```
6. Hand back to the referee, which re-runs every attack and every legitimate query.

## Hard rules
- Never `DROP` or `TRUNCATE` anything outside `LEAKHUNTER.SCRATCH`. Never delete rows in `DATA`.
- Never grant the analyst more access, and never revoke the analyst's baseline `SELECT` on `DATA.PATIENTS`, `DATA.VISITS`, `DATA.EMPLOYEES`.
- Never edit `LEAKHUNTER.RESULTS.ATTACK_RUNS` or `LEGIT_RUNS`. Only insert into `FIXES`.
- Only fix leaks that appear in the leak log. Explain anything else as a recommendation instead.
- One fix per root cause. If one masking policy closes several attacks, log it once per attack it closes.
