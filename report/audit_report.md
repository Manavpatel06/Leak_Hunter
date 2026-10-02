# LeakHunter audit report

Generated 2026-10-02 15:03 · warehouse `LEAKHUNTER` · all data synthetic

## Summary

- **11** attack(s) succeeded at least once across **2** round(s); **11** now proven closed, **0** still open.
- Leaks: **11** in round 1 → **0** in round 2.
- Legitimate analyst queries: **10/10** → **10/10** (no legitimate work broken).
- Planted for this test: L1, L2, L3, L4, L5, L6.

## Findings

| Attack | What leaked | Rule it breaks | Fix applied | Re-check |
|---|---|---|---|---|
| A01 (L1) | Patient SSNs were readable in clear text by the analyst role. | HIPAA Privacy Rule (minimum necessary) | masking by script: `ALTER TABLE LEAKHUNTER.DATA.PATIENTS MODIFY COLUMN SSN SET MASKING POLICY LEAKHUNTER.GOVERNANCE.MASK_SSN` | closed, proven in round 2 |
| A02 (L2) | Employee salaries could be read next to employee names. | GDPR Art. 5(1)(f) integrity and confidentiality; state privacy law | masking by script: `ALTER TABLE LEAKHUNTER.DATA.EMPLOYEES MODIFY COLUMN FULL_NAME SET MASKING POLICY LEAKHUNTER.GOVERNANCE.MASK_NAME` | closed, proven in round 2 |
| A03 (L3) | 'Anonymized' patient data (ZIP + birth date + sex) could be linked to free public census data to single out real people. | HIPAA de-identification standard (45 CFR 164.514) | masking by script: `ALTER TABLE LEAKHUNTER.DATA.PATIENTS MODIFY COLUMN ZIP SET MASKING POLICY LEAKHUNTER.GOVERNANCE.MASK_ZIP` | closed, proven in round 2 |
| A04 (L4) | The analyst role inherited the HR role and could read private performance reviews. | GDPR Art. 32 security of processing; least privilege | revoke by script: `REVOKE ROLE LH_HR FROM ROLE LH_ANALYST` | closed, proven in round 2 |
| A05 (L5) | A forgotten raw export of the patient table sat in SCRATCH, readable by the analyst. | HIPAA Privacy Rule (minimum necessary); GDPR Art. 32 security of processing | drop_scratch by script: `REVOKE USAGE ON SCHEMA LEAKHUNTER.SCRATCH FROM ROLE LH_ANALYST` | closed, proven in round 2 |
| A06 (L6) | A reporting view joined patient names to diagnoses. | HIPAA Privacy Rule (minimum necessary) | masking by script: `ALTER TABLE LEAKHUNTER.DATA.PATIENTS MODIFY COLUMN FULL_NAME SET MASKING POLICY LEAKHUNTER.GOVERNANCE.MASK_NAME` | closed, proven in round 2 |
| A07 | Sweep every readable table for SSN-like columns (catches tables nobody told us about) | HIPAA Privacy Rule (minimum necessary) | drop_scratch by script: `REVOKE USAGE ON SCHEMA LEAKHUNTER.SCRATCH FROM ROLE LH_ANALYST` | closed, proven in round 2 |
| G001 (L1) · gemma | Patient SSNs were readable in clear text by the analyst role. | HIPAA Privacy Rule (minimum necessary) | masking by script: `ALTER TABLE LEAKHUNTER.DATA.PATIENTS MODIFY COLUMN SSN SET MASKING POLICY LEAKHUNTER.GOVERNANCE.MASK_SSN` | closed, proven in round 2 |
| G002 (L2) · gemma | Employee salaries could be read next to employee names. | GDPR Art. 5(1)(f) integrity and confidentiality; state privacy law | masking by script: `ALTER TABLE LEAKHUNTER.DATA.EMPLOYEES MODIFY COLUMN FULL_NAME SET MASKING POLICY LEAKHUNTER.GOVERNANCE.MASK_NAME` | closed, proven in round 2 |
| G003 (L6) · gemma | A reporting view joined patient names to diagnoses. | HIPAA Privacy Rule (minimum necessary) | masking by script: `ALTER TABLE LEAKHUNTER.DATA.PATIENTS MODIFY COLUMN FULL_NAME SET MASKING POLICY LEAKHUNTER.GOVERNANCE.MASK_NAME` | closed, proven in round 2 |
| G004 (L4) · gemma | The analyst role inherited the HR role and could read private performance reviews. | GDPR Art. 32 security of processing; least privilege | revoke by script: `REVOKE ROLE LH_HR FROM ROLE LH_ANALYST` | closed, proven in round 2 |

## Rounds

| Round | Leaks | Attacks run | Legit passed |
|---|---|---|---|
| 1 | 11 | 12 | 10/10 |
| 2 | 0 | 12 | 10/10 |

In the latest round, 12 attack(s) were tried and blocked (see the scoreboard's Rejected panel).

Bouncer package checks: 10 blocked, 0 warned, 10 allowed.

---
_Method: attacks and legitimate queries run as the low-privilege `LH_ANALYST` role (secondary roles off); fixes are Snowflake-native (masking policies, revoked grants, dropped scratch copies). Sample rows from attacks are deliberately left out of this report. Regulation tags are pointers for a reviewer, not legal advice._
