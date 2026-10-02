# scoreboard/ — owner: Reya

`app.py` (Streamlit, run with `streamlit run scoreboard/app.py`), connects as `LH_ADMIN` via `leakhunter.db`.

Must show, auto-refreshing every few seconds:
1. Two big numbers for the latest round: **Leaks** (red when > 0) and **Legitimate queries working** (e.g. 10/10).
2. Round history from `RESULTS.SCOREBOARD` (e.g. Round 1: 6 leaks → Round 2: 0).
3. Latest leak log rows (goal, technique, evidence) and the latest fixes (`FIX_TYPE`, `SQL_APPLIED`, `APPLIED_BY`).
4. **Rejected panel:** attacks that failed (`SUCCEEDED = FALSE`) with the reason from `ERROR` or a short label (masked value returned, permission denied, invalid SQL). Shows what we refused to count as a leak.

Readable from 2 meters away: judges will be standing.
