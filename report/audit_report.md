# LeakHunter audit report

Generated 2026-10-02 14:24 · warehouse `LEAKHUNTER` · all data synthetic

## Summary

- **6** attack(s) succeeded at least once across **1** round(s); **0** now proven closed, **6** still open.
- Leaks: **6** in round 1 → **6** in round 1.
- Legitimate analyst queries: **10/10** → **10/10** (no legitimate work broken).
- Planted for this test: L1, L2, L3, L4, L5, L6.

## Findings

| Attack | What leaked | Rule it breaks | Fix applied | Re-check |
|---|---|---|---|---|
| A01 (L1) | Patient SSNs were readable in clear text by the analyst role. | HIPAA Privacy Rule (minimum necessary) | none logged | **OPEN** (still leaks in round 1) |
| A02 (L2) | Employee salaries could be read next to employee names. | GDPR Art. 5(1)(f) integrity and confidentiality; state privacy law | none logged | **OPEN** (still leaks in round 1) |
| A04 (L4) | The analyst role inherited the HR role and could read private performance reviews. | GDPR Art. 32 security of processing; least privilege | none logged | **OPEN** (still leaks in round 1) |
| A05 (L5) | A forgotten raw export of the patient table sat in SCRATCH, readable by the analyst. | HIPAA Privacy Rule (minimum necessary); GDPR Art. 32 security of processing | none logged | **OPEN** (still leaks in round 1) |
| A06 (L6) | A reporting view joined patient names to diagnoses. | HIPAA Privacy Rule (minimum necessary) | none logged | **OPEN** (still leaks in round 1) |
| A07 | Sweep every readable table for SSN-like columns (catches tables nobody told us about) | HIPAA Privacy Rule (minimum necessary) | none logged | **OPEN** (still leaks in round 1) |

## Rounds

| Round | Leaks | Attacks run | Legit passed |
|---|---|---|---|
| 1 | 6 | 7 | 10/10 |

In the latest round, 1 attack(s) were tried and blocked (see the scoreboard's Rejected panel).

Bouncer package checks: 2 blocked, 0 warned, 1 allowed.

---
_Method: attacks and legitimate queries run as the low-privilege `LH_ANALYST` role (secondary roles off); fixes are Snowflake-native (masking policies, revoked grants, dropped scratch copies). Sample rows from attacks are deliberately left out of this report. Regulation tags are pointers for a reviewer, not legal advice._
