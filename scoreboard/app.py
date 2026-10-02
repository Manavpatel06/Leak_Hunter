"""LeakHunter scoreboard. Reads LEAKHUNTER.RESULTS as LH_ADMIN and refreshes every few seconds.

Run from the repo root:  streamlit run scoreboard/app.py
Contract: docs/CONTRACTS.md §8. Spec: scoreboard/README.md.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

# `streamlit run` puts scoreboard/ on sys.path, not the repo root; add it so `leakhunter` imports.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from leakhunter import db  # noqa: E402

REFRESH = "3s"
RED, GREEN, GREY = "#d62828", "#2a9d8f", "#6c757d"

st.set_page_config(page_title="LeakHunter", page_icon="🛡️", layout="wide")
st.markdown(
    """
    <style>
      .block-container { padding-top: 1.5rem; }
      .lh-big { border-radius: 16px; padding: 18px 24px; color: white; text-align: center; }
      .lh-big .label { font-size: 1.6rem; font-weight: 600; opacity: .9; }
      .lh-big .value { font-size: 6rem; font-weight: 800; line-height: 1.05; }
      .lh-big .sub { font-size: 1.1rem; opacity: .85; }
      .lh-rounds { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; font-size: 1.4rem; }
      .lh-chip { border-radius: 10px; padding: 6px 14px; color: white; font-weight: 700; }
      .lh-arrow { color: #888; font-size: 1.6rem; }
      h3 { font-size: 1.6rem !important; }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource
def _admin_conn():
    return db.connect(db.ADMIN)


def frame(sql: str, params: dict | None = None) -> pd.DataFrame:
    """Run a query as LH_ADMIN; reconnect once if the cached connection went stale."""
    try:
        cols, rows = db.query(_admin_conn(), sql, params)
    except Exception:
        _admin_conn.clear()
        cols, rows = db.query(_admin_conn(), sql, params)
    return pd.DataFrame(rows, columns=cols)


def rejection_reason(row) -> str:
    """Short label for why a failed attack did not count as a leak."""
    err = str(row.get("ERROR") or "").lower()
    evidence = str(row.get("EVIDENCE") or "")
    if err:
        if "not authorized" in err or "insufficient privileges" in err or "permission" in err:
            return "Permission denied"
        if "read-only" in err or "read only" in err or "rejected" in err:
            return "Refused: not read-only SQL"
        if "syntax" in err or "invalid identifier" in err or "compilation" in err:
            return "Invalid SQL"
        if "is not set" in err or "placeholder" in err:
            return "Not configured yet"
        if err.startswith("chatbot:"):
            return "Chatbot unavailable"
        if "timeout" in err or "timed out" in err:
            return "Timed out"
        return "Error"
    if "***-**-" in evidence or "REDACTED" in evidence:
        return "Masked value returned"
    if not row.get("ROWS_RETURNED"):
        return "No rows returned"
    return "Ran, but success rule not met"


def big_number(label: str, value: str, sub: str, color: str) -> str:
    return (f'<div class="lh-big" style="background:{color}"><div class="label">{label}</div>'
            f'<div class="value">{value}</div><div class="sub">{sub}</div></div>')


def round_timeline(score: pd.DataFrame) -> str:
    chips = []
    for _, r in score.iterrows():
        leaks = None if pd.isna(r["LEAKS"]) else int(r["LEAKS"])
        color = GREY if leaks is None else (RED if leaks > 0 else GREEN)
        text = "…" if leaks is None else f"{leaks} leak{'s' if leaks != 1 else ''}"
        chips.append(f'<span class="lh-chip" style="background:{color}">Round {int(r["ROUND_NO"])}: {text}</span>')
    return '<div class="lh-rounds">' + '<span class="lh-arrow">→</span>'.join(chips) + "</div>"


@st.fragment(run_every=REFRESH)
def board() -> None:
    try:
        score = frame("SELECT ROUND_NO, LEAKS, ATTACKS, LEGIT_PASSED, LEGIT_TOTAL "
                      "FROM LEAKHUNTER.RESULTS.SCOREBOARD ORDER BY ROUND_NO")
    except Exception as e:  # keep the page up during the demo even if Snowflake hiccups
        st.error(f"Cannot read LEAKHUNTER.RESULTS.SCOREBOARD as LH_ADMIN: {e}\n\n"
                 "Check `.env` and run `python -m leakhunter.db`.")
        return

    if score.empty:
        st.info("No rounds yet. Waiting for the attacker: `python -m referee.run_round`")
        return

    latest = score.iloc[-1]
    rnd = int(latest["ROUND_NO"])

    # 1. Big numbers
    leaks = None if pd.isna(latest["LEAKS"]) else int(latest["LEAKS"])
    attacks = 0 if pd.isna(latest["ATTACKS"]) else int(latest["ATTACKS"])
    passed = None if pd.isna(latest["LEGIT_PASSED"]) else int(latest["LEGIT_PASSED"])
    total = None if pd.isna(latest["LEGIT_TOTAL"]) else int(latest["LEGIT_TOTAL"])
    c1, c2 = st.columns(2)
    c1.markdown(big_number(
        f"Leaks · round {rnd}", "—" if leaks is None else str(leaks),
        f"{attacks} attacks tried", GREY if leaks is None else (RED if leaks > 0 else GREEN)),
        unsafe_allow_html=True)
    c2.markdown(big_number(
        "Legitimate queries working", "—" if total is None else f"{passed}/{total}",
        "analyst workload, run as LH_ANALYST",
        GREY if total is None else (GREEN if passed == total else RED)),
        unsafe_allow_html=True)

    # 2. Round history
    st.markdown("### Round history")
    st.markdown(round_timeline(score), unsafe_allow_html=True)

    # 3. Leak log + latest fixes
    left, right = st.columns(2)
    with left:
        st.markdown(f"### Leaks proven in round {rnd}")
        leak_log = frame("SELECT ATTACK_ID, TARGETS_LEAK, GOAL, TECHNIQUE, SOURCE, EVIDENCE "
                         "FROM LEAKHUNTER.RESULTS.LEAK_LOG ORDER BY ATTACK_ID")
        if leak_log.empty:
            st.success("No leaks in the latest round.")
        else:
            st.dataframe(leak_log, hide_index=True, width="stretch")
    with right:
        fixes = frame("SELECT ROUND_NO, ATTACK_ID, FIX_TYPE, APPLIED_BY, SQL_APPLIED, RATIONALE, APPLIED_AT "
                      "FROM LEAKHUNTER.RESULTS.FIXES "
                      "WHERE ROUND_NO = (SELECT MAX(ROUND_NO) FROM LEAKHUNTER.RESULTS.FIXES) "
                      "ORDER BY APPLIED_AT DESC")
        if fixes.empty:
            st.markdown("### Fixes")
            st.caption("No fixes applied yet.")
        else:
            st.markdown(f"### Fixes after round {int(fixes.iloc[0]['ROUND_NO'])}")
            newest = fixes.iloc[0]
            st.caption(f"Latest: {newest['FIX_TYPE']} for {newest['ATTACK_ID']} by {newest['APPLIED_BY']}"
                       f" — {newest['RATIONALE'] or ''}")
            st.code(newest["SQL_APPLIED"] or "", language="sql")
            st.dataframe(fixes[["ATTACK_ID", "FIX_TYPE", "APPLIED_BY", "SQL_APPLIED"]],
                         hide_index=True, width="stretch")

    # Legit failures matter as much as leaks: call them out if any query broke.
    if total is not None and passed != total:
        broken = frame("SELECT QUERY_ID, DESCRIPTION, ERROR FROM LEAKHUNTER.RESULTS.LEGIT_RUNS "
                       "WHERE ROUND_NO = %(r)s AND NOT PASSED ORDER BY QUERY_ID", {"r": rnd})
        st.markdown(f"### ⚠️ Legitimate queries broken in round {rnd}")
        st.dataframe(broken, hide_index=True, width="stretch")

    # 4. Rejected panel
    st.markdown(f"### Rejected: what the attacker tried that did NOT count as a leak (round {rnd})")
    rejected = frame("SELECT ATTACK_ID, GOAL, TECHNIQUE, SOURCE, ROWS_RETURNED, EVIDENCE, ERROR "
                     "FROM LEAKHUNTER.RESULTS.ATTACK_RUNS "
                     "WHERE NOT SUCCEEDED AND ROUND_NO = %(r)s ORDER BY ATTACK_ID", {"r": rnd})
    if rejected.empty:
        st.caption("Every attack this round succeeded." if leaks else "No failed attacks this round.")
    else:
        rejected.insert(1, "REASON", rejected.apply(rejection_reason, axis=1))
        rejected["DETAIL"] = rejected["ERROR"].where(rejected["ERROR"].fillna("") != "", rejected["EVIDENCE"])
        st.dataframe(rejected[["ATTACK_ID", "REASON", "GOAL", "TECHNIQUE", "SOURCE", "DETAIL"]],
                     hide_index=True, width="stretch")


@st.fragment(run_every=REFRESH)
def firewall_panel() -> None:
    """Change Firewall: every change an AI agent proposed, BLOCKED or MERGED (RESULTS.CHANGE_AUDIT)."""
    try:
        audit = frame("SELECT CREATED_AT, CHANGE_ID, PARENT_ID, SUBMITTED_BY, VERDICT, MERGED, FINDINGS, CHANGE_SQL "
                      "FROM LEAKHUNTER.RESULTS.CHANGE_AUDIT ORDER BY CREATED_AT DESC LIMIT 10")
    except Exception:
        return  # table is created by the first `python -m firewall.leakcheck`; nothing to show before that
    if audit.empty:
        return
    st.markdown("### Change Firewall: what AI agents tried to change")

    def status(row) -> str:
        if row["VERDICT"] == "PASS":
            return "MERGED" if row["MERGED"] else "PASSED (not merged)"
        return "BLOCKED" if row["VERDICT"] == "BLOCK" else row["VERDICT"]

    def why(row) -> str:
        try:
            found = json.loads(row["FINDINGS"] or "{}").get("findings", [])
        except ValueError:
            return ""
        return "; ".join(f"{f['kind']}: {f['detail']}" for f in found if f.get("blocking"))[:200]

    audit["STATUS"] = audit.apply(status, axis=1)
    audit["WHY"] = audit.apply(why, axis=1)
    latest = audit.iloc[0]
    color = GREEN if latest["STATUS"] == "MERGED" else RED
    st.markdown(f'<div class="lh-rounds"><span class="lh-chip" style="background:{color}">'
                f'Latest change {latest["CHANGE_ID"]}: {latest["STATUS"]}</span></div>', unsafe_allow_html=True)
    st.dataframe(audit[["CREATED_AT", "STATUS", "SUBMITTED_BY", "WHY", "CHANGE_ID", "PARENT_ID"]],
                 hide_index=True, width="stretch")
    with st.expander("Latest proposed SQL"):
        st.code(latest["CHANGE_SQL"] or "", language="sql")


st.title("🛡️ LeakHunter")
st.caption("An AI attacks the warehouse, another fixes every leak, and a referee proves the fixes hold "
           "without breaking legitimate work. All data is synthetic.")
board()
firewall_panel()
