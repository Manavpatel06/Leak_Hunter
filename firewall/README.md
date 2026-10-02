# firewall/ — Change Firewall + Package Guard (owner: Reya)

Every change an AI agent (CoCo) wants to make to the warehouse is tested on a **zero-copy clone** first.
LeakHunter attacks the clone as `LH_ANALYST`; the change is merged only if nothing leaks.

```bash
python -m firewall.selftest                                   # offline proof the gate works (no Snowflake)
python -m firewall.leakcheck --sql-file firewall/examples/bad_patient_analytics.sql    # BLOCK + attack path
python -m firewall.leakcheck --sql-file firewall/examples/good_patient_analytics.sql --merge   # PASS + merge
python -m firewall.package_guard --sql-file firewall/examples/bad_package.sql          # BLOCK before cloning
```
`leakcheck` exit code: `0` PASS, `2` BLOCK, `3` firewall error. `--json` prints the full verdict for CoCo.

## Flow
0. **Package Guard** vets packages (`packages.yaml`): unapproved, typosquats, denied modules, stage `IMPORTS`, network egress.
1. **Static check**: only `CREATE VIEW/TABLE/FUNCTION/PROCEDURE/POLICY`, `ALTER TABLE/VIEW`, `GRANT`, `REVOKE`. `GRANT ROLE`,
   account-wide grants, and anything touching schemas other than `DATA`/`SCRATCH`/`GOVERNANCE` go to a human.
2. **Clone** `DATA`, `SCRATCH`, `GOVERNANCE` into `FW_<tag>_*` schemas (zero-copy), insert a **canary patient** (clone only).
3. **Baseline**: run the attack library on the clone before the change, so leaks that already existed are not blamed on it.
4. **Apply** the change to the clone (names rewritten `LEAKHUNTER.DATA.` → `LEAKHUNTER.FW_<tag>_DATA.`), grant `LH_ANALYST`
   read on what it created (worst case: it will be shared).
5. **Attack** as `LH_ANALYST`: the library again (a newly succeeding attack = BLOCK) + probes on every new object:
   SSNs, unmasked names, the canary record, and k-anonymity (groups smaller than 5 on ZIP / birth date / sex / age).
6. **Verdict**: PASS or BLOCK with `feedback.reasons[]` (`kind`, `why`, `fix`) and the `attack_path` transcript.
7. **PASS + `--merge`** applies the original SQL to production. Every attempt is saved in `RESULTS.CHANGE_AUDIT`
   (created on first use by `LH_ADMIN`; `PARENT_ID` links a rewrite to the attempt it fixes). Clones are always dropped.

## What this does not do (say it out loud)
- A PASS means "not breakable by these attacks", not "provably safe". Differencing attacks are not implemented yet.
- Enforcement in the demo comes from the `pii-guardian` skill telling CoCo to submit here. Real enforcement needs a
  Snowflake-side hook or proxy; that is the roadmap.
- Account-wide changes (role grants) cannot be tested on a clone, so they are always sent to a human.
- `sweep` and `chatbot` attacks are skipped in the clone (they scan the whole database); the object probes cover new objects.
- Views that were already in the warehouse and reference `LEAKHUNTER.DATA.*` by full name read production tables, not the clone.
- Needs only `LH_ADMIN` (owns the database); no extra grants. `CREATE SCHEMA ... CLONE` is cheap on the demo data.
