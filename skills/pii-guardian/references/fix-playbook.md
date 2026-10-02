# Fix playbook (pii-guardian)

Policies already exist in `LEAKHUNTER.GOVERNANCE` (created by `sql/00_setup.sql`). If one is
missing, recreate it with the definitions in `docs/CONTRACTS.md` §5.

| Root cause | Fix | SQL |
|---|---|---|
| Readable SSN column | Mask SSN | `ALTER TABLE LEAKHUNTER.DATA.<TABLE> MODIFY COLUMN SSN SET MASKING POLICY LEAKHUNTER.GOVERNANCE.MASK_SSN;` |
| Names next to sensitive data (salary, diagnosis) | Mask the name, keep the measure | `ALTER TABLE LEAKHUNTER.DATA.<TABLE> MODIFY COLUMN FULL_NAME SET MASKING POLICY LEAKHUNTER.GOVERNANCE.MASK_NAME;` |
| Re-identification via ZIP + birth date + sex | Generalize quasi-identifiers | `ALTER TABLE LEAKHUNTER.DATA.PATIENTS MODIFY COLUMN ZIP SET MASKING POLICY LEAKHUNTER.GOVERNANCE.MASK_ZIP;` and `ALTER TABLE LEAKHUNTER.DATA.PATIENTS MODIFY COLUMN DOB SET MASKING POLICY LEAKHUNTER.GOVERNANCE.MASK_DOB;` |
| Analyst inherits a broader role | Revoke inheritance | `REVOKE ROLE LH_HR FROM ROLE LH_ANALYST;` |
| Forgotten copy in SCRATCH | Revoke, then drop the copy | `REVOKE USAGE ON SCHEMA LEAKHUNTER.SCRATCH FROM ROLE LH_ANALYST;` then optionally `DROP TABLE LEAKHUNTER.SCRATCH.<TABLE>;` |
| Rows the analyst should never see at all | Row access policy | `CREATE ROW ACCESS POLICY LEAKHUNTER.GOVERNANCE.<NAME> AS (<COL> STRING) RETURNS BOOLEAN -> IS_ROLE_IN_SESSION('LH_ADMIN') OR <condition>;` then `ALTER TABLE ... ADD ROW ACCESS POLICY ... ON (<COL>);` |

Notes
- A column can hold only one masking policy. If one is already set, `UNSET` it first.
- Masking on a base column also protects every view over that column.
- Masked values were chosen so legitimate queries keep working: `LEFT(ZIP,3)`, `YEAR(DOB)`, `AVG(SALARY)` all still work.
- Copies made with `CREATE TABLE AS SELECT` by an admin contain raw values; masking the source does not protect the copy.

## Regulation tags (for the audit report; plain-English, verify before presenting)
| Leak type | Tag |
|---|---|
| Patient identifiers or diagnoses exposed | HIPAA Privacy Rule (minimum necessary) |
| Re-identifiable "de-identified" data | HIPAA de-identification standard (45 CFR 164.514) |
| Employee SSN / salary by name | GDPR Art. 5(1)(f) integrity and confidentiality; state privacy law |
| Over-broad roles, forgotten copies | GDPR Art. 32 security of processing; least-privilege control |
