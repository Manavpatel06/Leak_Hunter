# CoCo defender run — paste-ready (owner: Manav)

**Before:** Snowsight → role `LH_ADMIN`, warehouse `LH_WH`. A round has just run (`python -m referee.run_round`).
Open CoCo (Cortex Code) and attach or paste `skills/pii-guardian/SKILL.md` and
`skills/pii-guardian/references/fix-playbook.md`.

## Prompt

> You are the defender for the LeakHunter demo. Follow the attached pii-guardian skill exactly.
> Use role LH_ADMIN and warehouse LH_WH.
> 1. Run `SELECT ATTACK_ID, TECHNIQUE, TARGETS_LEAK, SQL_TEXT, EVIDENCE FROM LEAKHUNTER.RESULTS.LEAK_LOG;`
> 2. For each row, name the root cause in one line, then apply the smallest fix from the playbook.
>    Check first with `SELECT * FROM TABLE(LEAKHUNTER.INFORMATION_SCHEMA.POLICY_REFERENCES(REF_ENTITY_NAME => 'LEAKHUNTER.DATA.PATIENTS', REF_ENTITY_DOMAIN => 'table'));`
>    so you never set a policy that is already set.
> 3. After each fix, insert one row into LEAKHUNTER.RESULTS.FIXES per attack it closes, using the
>    INSERT template in the skill, with APPLIED_BY = 'coco' and the exact SQL you ran.
> 4. Do not drop anything outside LEAKHUNTER.SCRATCH, do not unset any masking policy, do not run the
>    attack SQL, and do not touch the analyst's SELECT on DATA.PATIENTS, DATA.VISITS, DATA.EMPLOYEES.
> 5. Finish with a table: attack → root cause → fix → fix type.

## Expected fixes for `plant_leaks --all`
| Attack | Fix |
|---|---|
| A01 | `MASK_SSN` on `DATA.PATIENTS.SSN` |
| A02 | `MASK_NAME` on `DATA.EMPLOYEES.FULL_NAME` |
| A03 | `MASK_ZIP` on `PATIENTS.ZIP` + `MASK_DOB` on `PATIENTS.DOB` |
| A04 | `REVOKE ROLE LH_HR FROM ROLE LH_ANALYST` |
| A05, A07 | `REVOKE USAGE ON SCHEMA LEAKHUNTER.SCRATCH FROM ROLE LH_ANALYST` + drop the SCRATCH copy |
| A06 | `MASK_NAME` on `DATA.PATIENTS.FULL_NAME` |

**After:** screenshot the CoCo conversation + one policy it applied into `docs/coco/`, then
`python -m referee.run_round` (expect 0 leaks, legit all pass).
**If CoCo stalls > 2 min on stage:** `python -m defender.apply_fixes` (same fixes, `APPLIED_BY = 'script'`).
