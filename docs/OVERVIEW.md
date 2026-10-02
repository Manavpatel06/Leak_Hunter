# LeakHunter: project overview

*sunhacks Hack Day, October 2, 2026 · Tracks: Best Use of Snowflake, Best Open-Source AI Project · MIT licensed*
*Team: Reya Attri, Manav, Manas · All data is synthetic*

**One AI attacks your Snowflake warehouse, another fixes every leak, and a referee proves the fixes hold without breaking anyone's legitimate work. Then two gates keep AI agents from opening new leaks: one for the changes they make, one for the packages they install.**

Interactive version of everything below: open [`showcase.html`](showcase.html) in a browser.

---

## 1. The problem

Security scanners tell you *where* sensitive data is. They do not tell you whether someone can actually *reach* it, and they cannot prove a fix works. At the same time, AI agents are being given write access to warehouses and the power to install code. Two questions follow, and buyers ask them:

1. What stops an agent from creating a view that leaks customers?
2. What stops an agent from installing a package that does not exist, or one an attacker registered to catch it?

## 2. What LeakHunter does

| Part | What it does | Owner |
|---|---|---|
| **Warehouse** | A synthetic hospital + HR warehouse (2,000 patients, 6,000 visits, 300 employees) with six planted leaks, next to Snowflake's free public census data | Manav |
| **Attacker** | Seven hand-written attacks plus Gemma-generated ones, run as a low-privilege role (`LH_ANALYST`, secondary roles off) | Manas |
| **Defender** | CoCo with the open `pii-guardian` skill applies the smallest Snowflake-native fix: masking, revoke, drop | Manav |
| **Referee** | Re-runs every attack and ten legitimate analyst queries each round. Success is leaks falling to zero while legitimate work still passes | Manas |
| **Scoreboard** | Streamlit: leaks, legitimate queries working, round history, latest fixes, and a Rejected panel of attacks that failed and why | Reya |
| **Bouncer** | A second skill that vets a Python package before an AI installs it | Reya |
| **Change Firewall** | Tests every agent-proposed change on a clone and merges it only if nothing leaks | Reya |
| **Report** | Plain-English audit, each leak tagged to the rule it breaks | Manav |

## 3. The leak catalog

| ID | Leak | Fix |
|---|---|---|
| L1 | Patient SSNs readable | Masking policy on `PATIENTS.SSN` |
| L2 | Salaries readable by name | Mask `EMPLOYEES.FULL_NAME`, keep `SALARY` so averages still work |
| L3 | "Anonymized" patients re-identifiable by joining with public census data | Generalize ZIP and birth date |
| L4 | Analyst role inherits the HR role | Revoke the role |
| L5 | Forgotten raw export in `SCRATCH` | Revoke access to the schema |
| L6 | A reporting view joins names to diagnoses | Mask names at the base column |

Masking was chosen so legitimate aggregates survive: `LEFT(ZIP,3)`, `YEAR(DOB)` and `AVG(SALARY)` keep working after the fixes.

## 4. Results from the live warehouse

The full loop has been run on the live warehouse and is logged in `RESULTS`:

| Round | Leaks | Legitimate queries |
|---|---|---|
| 1 (before any fix) | **11 of 12 attacks leak** | 10 / 10 pass |
| 2 (after the defender's 11 logged fixes) | **0 leaks** | **10 / 10 still pass** |

- The fixes in `RESULTS.FIXES` were applied by the `defender/apply_fixes.py` fallback script. A run with CoCo and the `pii-guardian` skill is still to be shown.
- Attack A03 re-identifies patients by joining the "anonymized" view with the free public ZIP population table.
- One Gemma-generated attack (G005) found nothing readable, which the scoreboard shows in its Rejected panel. A failed or erroring query is never counted as a leak.
- With full ZIP, full birth date and sex, **all 2,000 patients are unique**. Generalizing to a 3-digit ZIP and birth decade, and dropping any group smaller than 5, leaves everyone hiding in a group of at least 5 (about 4.7% of patients are dropped from the view). The dashboard's re-identification lab lets you move those sliders yourself.

## 5. Change Firewall

Every change an AI agent wants to make is tested before it touches production.

```
agent proposes SQL
   ↓
0  Package Guard + Bouncer     packages checked against policy and live PyPI
1  Static check                only change types the firewall can sandbox
2  Zero-copy clone             only the schema the change names, plus a canary patient
3  Baseline attacks            run on production while the clone builds, so old leaks are not blamed on the change
4  Apply to the clone only
5  Attack as LH_ANALYST        library attacks again, plus probes on every new object
6  Verdict                     PASS or BLOCK, with evidence and machine-readable feedback
   ↓
BLOCK: the agent rewrites and resubmits      PASS + --merge: applied to production
every attempt is saved to RESULTS.CHANGE_AUDIT
```

The probes on a new view or table look for: full SSNs, real names, the canary patient, and any combination of ZIP, birth date, sex or age shared by fewer than 5 people.

**Demonstrated live:**

| Submission | Verdict | Time |
|---|---|---|
| View exposing ZIP + birth date + sex | **BLOCK**: 4,188 of 5,000 rows re-identifiable | ~14 s |
| Same view rewritten (3-digit ZIP, decade, groups of 5+) | **PASS** | ~13 s |
| Function using a typosquatted package and network access | **BLOCK** before any clone | ~4 s |
| `GRANT ROLE LH_HR TO ROLE LH_ANALYST` | **BLOCK**: account-wide, sent to a human | ~4 s |

Failures fail closed: if the clone cannot be made or anything unexpected happens, the verdict is ERROR, never PASS, and production is untouched.

## 6. Bouncer

AI assistants sometimes recommend packages that do not exist; attackers can register those names and wait. Bouncer reads PyPI metadata (it never installs anything) and returns ALLOW, WARN or BLOCK:

| Check | Verdict |
|---|---|
| Package not on PyPI (likely invented) | BLOCK |
| Name one or two letters from a popular package | WARN |
| First published under 30 days ago, or under 90 days with a single release | WARN |
| Known vulnerabilities on the latest version | WARN |

If PyPI cannot be reached it fails closed (WARN). Verdicts go to `RESULTS.BOUNCER_LOG` and appear on the scoreboard. Inside the firewall, Bouncer is asked about every package the policy does not already approve, so approved packages skip the network.

## 7. Run it

```bash
python demo/run_demo.py doctor       # preflight: env, key, both roles, tables, Ollama, PyPI
python demo/run_demo.py round        # one referee round
python demo/run_demo.py agent        # Bouncer, then firewall BLOCK, then PASS
python demo/run_demo.py scoreboard   # live scoreboard
python demo/build_showcase.py        # rebuild the interactive dashboard from live data
python -m firewall.selftest          # offline proof the firewall logic works, no Snowflake needed
```

Setup, secrets and who owns what are in the [README](../README.md) and [`PLAN.md`](PLAN.md); shared names and file formats are in [`CONTRACTS.md`](CONTRACTS.md).

## 8. Honest limits

- A PASS means **not breakable by these attacks**, not provably safe. Differencing attacks are not built yet.
- In the demo the `pii-guardian` skill tells CoCo to submit changes to the firewall. Real enforcement needs a Snowflake-side hook or proxy; that is the roadmap.
- Account-wide changes such as role grants cannot be tested on a clone, so they always go to a human.
- Cloning a large database could be slow or costly. The demo warehouse is small, and roughly 5 of the firewall's ~14 seconds is Snowflake cloning one schema.
- Bouncer catches invented, look-alike, brand-new and known-vulnerable packages. It does not catch a long-trusted package that was later hijacked; maintainer-history checks are on the roadmap.
- Regulation tags in the audit report are plain-English pointers, not legal advice.
- Similar ideas exist (agent change governance, sandbox-validated changes, masking tooling for agents). To our knowledge, none attacks a proposed change for re-identification on a clone before approving it. Expect this space to be crowded.

## 9. Repository map

| Path | Contents |
|---|---|
| `sql/`, `setup/` | Snowflake objects, synthetic data, leak planting |
| `attacks/`, `attacker/`, `referee/` | Attack library, Gemma attacker, round engine |
| `defender/`, `skills/pii-guardian/` | The fix skill and defender run |
| `skills/bouncer/` | The Bouncer skill |
| `firewall/` | Change Firewall, Package Guard, probes, examples, offline self-test |
| `scoreboard/` | Streamlit scoreboard |
| `demo/`, `docs/showcase.html` | Demo runner and the interactive dashboard |
| `report/` | Audit report generator |
| `leakhunter/` | Shared config and database helpers |
