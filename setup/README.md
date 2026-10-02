# setup/ — owner: Manav

## Tasks
1. `generate_data.py` — create and fill `DATA.PATIENTS`, `VISITS`, `EMPLOYEES`, `EMPLOYEE_REVIEWS` exactly as in CONTRACTS §3 (run as `LH_ADMIN`). Fake SSNs `9XX-XX-XXXX`. Use real Arizona ZIPs, including some small rural ZIPs picked from the public table. Then grant baseline: `GRANT SELECT ON TABLE DATA.PATIENTS, DATA.VISITS, DATA.EMPLOYEES TO ROLE LH_ANALYST;` and `GRANT SELECT ON TABLE DATA.EMPLOYEE_REVIEWS TO ROLE LH_HR;`
2. `plant_leaks.py --all | --random N --seed S` — plant L1–L6 (CONTRACTS §5), record each in `RESULTS.PLANTED`.
3. `reset.py` — unset all masking policies, revoke planted grants, drop planted views/scratch tables, truncate RESULTS tables. Lets us rehearse the demo repeatedly.

## Done when
`python -m setup.generate_data && python -m setup.plant_leaks --all` from a clean account, then Manas's `referee.run_round` shows every library attack succeeding.
