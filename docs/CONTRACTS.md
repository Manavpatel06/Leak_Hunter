# CONTRACTS — shared names and formats (source of truth)

Everything here is fixed. Code must use these exact names. To change anything, post in the group
first, then update this file in one commit titled `[contracts] ...`.

## 1. Snowflake objects

| Thing | Name |
|---|---|
| Database | `LEAKHUNTER` |
| Warehouse | `LH_WH` (X-Small, auto-suspend 60 s) |
| Schemas | `DATA` (synthetic warehouse) · `SCRATCH` (forgotten copies, exports) · `GOVERNANCE` (policies) · `RESULTS` (logs, scoreboard) |
| Roles | `LH_ADMIN` (defender + logging, owns everything) · `LH_ANALYST` (attacker; also the role legit queries run as) · `LH_HR` (HR-only data; used for leak L4) |
| Service user | `LH_BOT` (key-pair auth, has `LH_ADMIN` + `LH_ANALYST`) |
| Policies | `GOVERNANCE.MASK_SSN`, `GOVERNANCE.MASK_NAME`, `GOVERNANCE.MASK_ZIP`, `GOVERNANCE.MASK_DOB` |

Created by `sql/00_setup.sql`. Always fully qualify names in SQL: `LEAKHUNTER.DATA.PATIENTS`.

## 2. Access model

- **Attacks and legit queries run as `LH_ANALYST` with `USE SECONDARY ROLES NONE`.** `leakhunter.db.connect(ANALYST)` does this. Without it, the service user's other roles leak into the session and every attack falsely succeeds.
- **Baseline (legitimate) analyst access:** `SELECT` on `DATA.PATIENTS`, `DATA.VISITS`, `DATA.EMPLOYEES`. The analyst's job needs aggregates over these tables. The leaks are the *unprotected columns and extra grants*, not the baseline access.
- **Masking rule:** a policy shows the real value only when `IS_ROLE_IN_SESSION('LH_ADMIN')`.

## 3. Synthetic data (`LEAKHUNTER.DATA`)

| Table | Columns | Rows |
|---|---|---|
| `PATIENTS` | `PATIENT_ID STRING, FULL_NAME STRING, SSN STRING, DOB DATE, SEX STRING ('F'/'M'), ZIP STRING (5 digits), PHONE STRING` | 2,000 |
| `VISITS` | `VISIT_ID STRING, PATIENT_ID STRING, VISIT_DATE DATE, DEPARTMENT STRING, DIAGNOSIS_CODE STRING, DIAGNOSIS_DESC STRING, COST NUMBER(10,2)` | 6,000 |
| `EMPLOYEES` | `EMP_ID STRING, FULL_NAME STRING, SSN STRING, DEPARTMENT STRING, TITLE STRING, SALARY NUMBER(10,2), HIRE_DATE DATE` | 300 |
| `EMPLOYEE_REVIEWS` | `EMP_ID STRING, REVIEW_YEAR INT, RATING INT, MANAGER_NOTES STRING` | 600 |

- Fake SSNs: format `9XX-XX-XXXX` (900–999 area numbers are never issued as real SSNs).
- ZIPs: real Arizona 5-digit ZIPs, mixing dense metro ZIPs with some small rural ZIPs (pick small ones from the public table in §4) so re-identification is realistic.

## 4. Free public dataset (Snowflake track requirement)

- Listing: **Snowflake Public Data (Free)** from Marketplace. Do not rename its database.
- Needed: population by ZIP code (ideally by age band and sex) from the Data Commons / Census sources.
- **Found (Manav):** listing database `SNOWFLAKE_PUBLIC_DATA_FREE`, view `PUBLIC_DATA_FREE.AMERICAN_COMMUNITY_SURVEY_TIMESERIES`
  (`GEO_ID` like `'zip/85281'`, `VARIABLE`, `DATE`, `VALUE`). Total population = `VARIABLE = 'B01003_001E_5YR'` (ACS 5-year).
- **Use this table:** `LEAKHUNTER.DATA.ZIP_POPULATION (ZIP STRING, POPULATION INT, AS_OF DATE)`, one row per Arizona ZIP,
  latest estimate, built by `sql/02_zip_population.sql`. `LH_ANALYST` can read it (it is public data). No real ZIP in it ends in `00`.
- Env var `LH_PUBLIC_ZIP_TABLE=LEAKHUNTER.DATA.ZIP_POPULATION`.
- A03 SQL (Manas):
  ```sql
  SELECT COUNT(*) AS REIDENTIFIABLE
  FROM (SELECT ZIP, YEAR(DOB) AS BIRTH_YEAR, SEX FROM LEAKHUNTER.DATA.PATIENT_DEMOGRAPHICS
        GROUP BY 1, 2, 3 HAVING COUNT(*) = 1) U
  JOIN LEAKHUNTER.DATA.ZIP_POPULATION P ON P.ZIP = U.ZIP
  WHERE P.POPULATION < 5000
  ```
  `PATIENT_DEMOGRAPHICS` is one row per patient. After the L3 fix, ZIP shows as `XXX00`, so the join finds nothing.
- Fallback if only total population per ZIP exists: re-identification = patients unique on (ZIP, birth year, sex) inside our data whose ZIP has a small public population.

## 5. Leak catalog (what `setup/plant_leaks.py` creates)

| ID | Leak | How it's planted | Library attack | Expected fix |
|---|---|---|---|---|
| L1 | Patient SSNs readable | No masking on `PATIENTS.SSN` | `A01` | `MASK_SSN` on `PATIENTS.SSN` |
| L2 | Salaries by name | No masking on `EMPLOYEES.FULL_NAME` | `A02` | `MASK_NAME` on `EMPLOYEES.FULL_NAME` (keep `SALARY` visible so averages still work) |
| L3 | Re-identification | View `DATA.PATIENT_DEMOGRAPHICS` (`PATIENT_ID, DOB, SEX, ZIP, DIAGNOSIS_DESC`, no names) granted to analyst | `A03` | `MASK_ZIP` + `MASK_DOB` on `PATIENTS.ZIP` / `PATIENTS.DOB` (policies follow columns into views) |
| L4 | Role too broad | `GRANT ROLE LH_HR TO ROLE LH_ANALYST`; `LH_HR` reads `EMPLOYEE_REVIEWS` | `A04` | `REVOKE ROLE LH_HR FROM ROLE LH_ANALYST` |
| L5 | Forgotten export | `SCRATCH.PATIENTS_EXPORT_OLD` = raw copy of `PATIENTS` (made before masking), analyst can read `SCRATCH` | `A05` | `REVOKE` analyst access to `SCRATCH` (or `DROP` the scratch table) |
| L6 | Harmless tables joined | View `DATA.VISIT_DETAILS` joining `VISITS` + `PATIENTS` exposing `FULL_NAME` + `DIAGNOSIS_DESC` | `A06` | `MASK_NAME` on `PATIENTS.FULL_NAME` |

Masking outputs (chosen so legit aggregate queries keep working):

| Policy | Non-admin sees |
|---|---|
| `MASK_SSN` | `'***-**-' \|\| RIGHT(val, 4)` |
| `MASK_NAME` | `'REDACTED'` |
| `MASK_ZIP` | `LEFT(val, 3) \|\| '00'` |
| `MASK_DOB` | `DATE_FROM_PARTS(YEAR(val), 1, 1)` |

`plant_leaks.py` flags: `--all` (demo default) or `--random N --seed S`. It writes what it planted to `RESULTS.PLANTED` (the answer key; analyst cannot read it).

## 6. Attack file format (`attacks/library/*.yaml`, `attacks/generated/*.yaml`)

```yaml
id: A01                       # library: A01..A99 · generated: G001.. · judge: J01..
goal: "Read any patient SSN"
technique: direct_sql         # direct_sql | join | reidentification | role_escalation | sweep | chatbot
source: library               # library | gemma | judge
targets_leak: L1              # optional; which catalog leak it aims at
sql: |                        # required unless technique is sweep or chatbot
  SELECT FULL_NAME, SSN FROM LEAKHUNTER.DATA.PATIENTS LIMIT 5
success:
  type: regex                 # regex | nonempty | min_value
  column: SSN                 # regex: column to test · min_value: numeric column
  pattern: '^\d{3}-\d{2}-\d{4}$'   # regex: succeeds if ANY returned value fully matches
  # min_value: succeeds if the column's first-row value >= threshold
  # threshold: 1
```

- `sweep`: no `sql`; instead `column_pattern: '%SSN%'`. The runner lists every column the analyst can see via `LEAKHUNTER.INFORMATION_SCHEMA.COLUMNS` matching the pattern, selects 5 rows from each, and applies `success`. This catches new tables nobody told us about (the judge's export).
- `chatbot` (stretch): no `sql`; instead `prompt: "Which patients over 90 live in 85281?"`. The runner sends it to `chatbot/` and applies `success` to whatever comes back.
- A failed or erroring query counts as **not succeeded** (log the error).
- Attack SQL must be read-only (`SELECT` / `WITH` / `SHOW`). The runner rejects anything else.

## 7. Legit query format (`legit/queries.yaml`)

```yaml
- id: Q01
  description: "Visit count per department per month"
  sql: |
    SELECT DEPARTMENT, DATE_TRUNC('MONTH', VISIT_DATE) AS M, COUNT(*) AS N
    FROM LEAKHUNTER.DATA.VISITS GROUP BY 1, 2
  expect: nonempty             # nonempty | no_error
```

Rules: aggregates only, run as `LH_ANALYST`, and must keep passing **after** the fixes in §5 (e.g. group by `LEFT(ZIP,3)` and `YEAR(DOB)`, average `SALARY` by `DEPARTMENT`; never select names or SSNs).

## 8. RESULTS tables (written only through `leakhunter/db.py`)

| Table | Columns |
|---|---|
| `ATTACK_RUNS` | `RUN_ID, ROUND_NO, ATTACK_ID, GOAL, TECHNIQUE, SOURCE, TARGETS_LEAK, SQL_TEXT, SUCCEEDED, ROWS_RETURNED, EVIDENCE, ERROR, RAN_AT` |
| `LEGIT_RUNS` | `RUN_ID, ROUND_NO, QUERY_ID, DESCRIPTION, PASSED, ERROR, RAN_AT` |
| `FIXES` | `FIX_ID, ROUND_NO, ATTACK_ID, FIX_TYPE, SQL_APPLIED, RATIONALE, APPLIED_BY, APPLIED_AT` |
| `PLANTED` | `LEAK_ID, DESCRIPTION, PLANTED_AT` |
| `BOUNCER_LOG` | `CHECK_ID, PACKAGE, ECOSYSTEM, VERDICT, REASONS, REQUESTED_BY, CHECKED_AT` · `VERDICT` ∈ `ALLOW | WARN | BLOCK` · `REQUESTED_BY` ∈ `coco | gemma | claude | human` |

Views: `RESULTS.LEAK_LOG` (successful attacks in the latest round; what the defender reads) and `RESULTS.SCOREBOARD` (per round: `LEAKS`, `ATTACKS`, `LEGIT_PASSED`, `LEGIT_TOTAL`).

**Round rules**
1. `referee.run_round` starts round N = `db.next_round()`, runs all attacks + all legit queries, tagged N.
2. Defender fixes the leaks in `LEAK_LOG` and logs each fix with `ROUND_NO = N`.
3. `referee.run_round` again → round N+1 is the re-check.
4. Judge break → run round, fix, run round again.

`EVIDENCE` = first 3 rows as text, max 300 characters. `FIX_TYPE` ∈ `masking | row_access | revoke | drop_scratch | secure_view`. `APPLIED_BY` ∈ `coco | script | human`.

## 9. Environment variables (`.env`, never committed)

| Var | Example |
|---|---|
| `SNOWFLAKE_ACCOUNT` | `orgname-accountname` |
| `SNOWFLAKE_USER` | `LH_BOT` |
| `SNOWFLAKE_PRIVATE_KEY_FILE` | `./secrets/lh_bot_key.p8` (preferred) |
| `SNOWFLAKE_PASSWORD` | only if not using a key |
| `SNOWFLAKE_WAREHOUSE` | `LH_WH` |
| `SNOWFLAKE_DATABASE` | `LEAKHUNTER` |
| `OLLAMA_MODEL` | smallest Gemma that writes valid SQL (check `ollama list`) |
| `OLLAMA_HOST` | `http://localhost:11434` |
| `LH_PUBLIC_ZIP_TABLE` | fully qualified public table from §4 |

## 10. Service user key (Manav, once)

Run in Git Bash (has openssl) or any terminal with openssl:
```bash
mkdir -p secrets
openssl genrsa 2048 | openssl pkcs8 -topk8 -inform PEM -out secrets/lh_bot_key.p8 -nocrypt
openssl rsa -in secrets/lh_bot_key.p8 -pubout -out secrets/lh_bot_key.pub
```
Then in Snowsight as ACCOUNTADMIN: `ALTER USER LH_BOT SET RSA_PUBLIC_KEY='<contents of .pub without the BEGIN/END lines>';`
Send `lh_bot_key.p8` + `.env` values to teammates **privately (DM)**. `secrets/` is gitignored.

## 11. Bouncer (owner: Reya)
- Skill: `skills/bouncer/SKILL.md`; check: `python skills/bouncer/scripts/check.py <pkg> ... [--log] [--by <agent>]`.
- Output: one JSON line per package `{"package", "verdict", "reasons"}`; exit code 0 ALLOW, 1 WARN, 2 BLOCK.
- Logging via `db.log_bouncer`. Details and tasks: `docs/BOUNCER.md`.

## 12. Links
- MLH submission: https://www.mlh.com/events/hacktoberfest-hack-day-tempe-x-sunhacks/submissions/new
- Event Discord: https://discord.gg/SFmUNjPjb
- Agent Skill standard: https://agentskills.io (validate with `skills-ref validate ./skills/pii-guardian`)
