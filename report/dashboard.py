"""Static showcase dashboard (owner: Manav). Reads LEAKHUNTER.RESULTS as LH_ADMIN (read-only) and writes
ONE self-contained file, report/dashboard.html: no server, no internet, opens in any browser.
Good for judges, the repo, and the MLH submission. The live Streamlit scoreboard stays the stage view.

    python -m report.dashboard            # -> report/dashboard.html (+ report/dashboard_data.json)

Privacy: attack EVIDENCE (sample rows) is never included. Only counts, IDs, goals and fix SQL.
"""
from __future__ import annotations

import datetime as dt
import html
import json
from pathlib import Path

from report.generate import ATTACK_TO_LEAK, LEAK_TAGS, LEAK_TEXT, _tags

OUT_HTML = Path("report/dashboard.html")
OUT_JSON = Path("report/dashboard_data.json")


def _jsonable(v):
    if isinstance(v, (dt.date, dt.datetime)):
        return v.isoformat(sep=" ") if isinstance(v, dt.datetime) else v.isoformat()
    if hasattr(v, "is_integer") or type(v).__name__ == "Decimal":
        f = float(v)
        return int(f) if f.is_integer() else f
    return v


def fetch() -> dict:
    from leakhunter import db

    conn = db.connect(db.ADMIN)

    def rows(sql: str) -> list[dict]:
        try:
            cols, rs = db.query(conn, sql)
            return [{c: _jsonable(v) for c, v in zip(cols, r)} for r in rs]
        except Exception as e:  # optional tables (Bouncer, firewall) may not exist yet
            print(f"  (skipped: {str(e).splitlines()[0][:90]})")
            return []

    try:
        return {
            "generated_at": dt.datetime.now().strftime("%Y-%m-%d %H:%M"),
            "scoreboard": rows("SELECT ROUND_NO, LEAKS, ATTACKS, LEGIT_PASSED, LEGIT_TOTAL "
                               "FROM LEAKHUNTER.RESULTS.SCOREBOARD ORDER BY ROUND_NO"),
            "attacks": rows("SELECT ROUND_NO, ATTACK_ID, GOAL, TECHNIQUE, SOURCE, TARGETS_LEAK, SUCCEEDED, "
                            "ROWS_RETURNED, LEFT(ERROR, 160) AS ERROR "
                            "FROM LEAKHUNTER.RESULTS.ATTACK_RUNS ORDER BY ROUND_NO, ATTACK_ID"),
            "legit": rows("SELECT ROUND_NO, QUERY_ID, DESCRIPTION, PASSED FROM LEAKHUNTER.RESULTS.LEGIT_RUNS "
                          "ORDER BY ROUND_NO, QUERY_ID"),
            "fixes": rows("SELECT ROUND_NO, ATTACK_ID, FIX_TYPE, SQL_APPLIED, RATIONALE, APPLIED_BY "
                          "FROM LEAKHUNTER.RESULTS.FIXES ORDER BY APPLIED_AT"),
            "planted": rows("SELECT LEAK_ID FROM LEAKHUNTER.RESULTS.PLANTED ORDER BY LEAK_ID"),
            "bouncer": rows("SELECT PACKAGE, VERDICT, LEFT(REASONS, 200) AS REASONS, REQUESTED_BY "
                            "FROM LEAKHUNTER.RESULTS.BOUNCER_LOG ORDER BY CHECKED_AT DESC LIMIT 15"),
            "firewall": rows("SELECT CHANGE_ID, SUBMITTED_BY, VERDICT, MERGED, LEFT(FINDINGS, 240) AS FINDINGS "
                             "FROM LEAKHUNTER.RESULTS.CHANGE_AUDIT ORDER BY CREATED_AT DESC LIMIT 10"),
            "reidentified": rows("SELECT COUNT(*) AS N FROM (SELECT ZIP, YEAR(DOB) AS Y, SEX "
                                 "FROM LEAKHUNTER.DATA.PATIENTS GROUP BY 1, 2, 3 HAVING COUNT(*) = 1) U "
                                 "JOIN LEAKHUNTER.DATA.ZIP_POPULATION P ON P.ZIP = U.ZIP "
                                 "WHERE P.POPULATION BETWEEN 0 AND 4999"),
        }
    finally:
        conn.close()


# ------------------------------------------------------------------ rendering
FIX_PLAIN = {
    "L1": "Masked the SSN column. The analyst now sees ***-**-1234.",
    "L2": "Masked employee names. Salaries stay visible, so averages still work.",
    "L3": "Generalized ZIP to 3 digits and birth date to the year. The Census join finds no one.",
    "L4": "Revoked the HR role from the analyst role.",
    "L5": "Revoked analyst access to SCRATCH and dropped the stale copy.",
    "L6": "Masked patient names. Diagnoses stay usable for reporting.",
}
LEAK_SHORT = {
    "L1": "Patient SSNs readable", "L2": "Salaries readable by name", "L3": "“Anonymous” patients re-identified",
    "L4": "HR reviews reachable via a role grant", "L5": "Forgotten raw export in SCRATCH",
    "L6": "Names joined to diagnoses in a view",
}


def e(v) -> str:
    return html.escape("" if v is None else str(v))


def _findings_kind(raw) -> str:
    try:
        f = json.loads(raw or "{}").get("findings") or []
        return f[0].get("kind", "").replace("_", " ") if f else "no leak found on the clone"
    except Exception:
        return "see audit trail"


def build_html(d: dict) -> str:
    board, attacks, fixes = d["scoreboard"], d["attacks"], d["fixes"]
    first, last = (board[0], board[-1]) if board else ({}, {})
    reid = d["reidentified"][0]["N"] if d.get("reidentified") else None
    leaks0, leaks1 = int(first.get("LEAKS") or 0), int(last.get("LEAKS") or 0)
    lp, lt = int(last.get("LEGIT_PASSED") or 0), int(last.get("LEGIT_TOTAL") or 0)

    # group successful attacks by leak
    runs: dict[str, dict[int, bool]] = {}
    meta: dict[str, dict] = {}
    for a in attacks:
        r = runs.setdefault(a["ATTACK_ID"], {})
        r[int(a["ROUND_NO"])] = r.get(int(a["ROUND_NO"]), False) or bool(a["SUCCEEDED"])
        meta.setdefault(a["ATTACK_ID"], a)
    fix_by = {f["ATTACK_ID"]: f for f in fixes}
    groups: dict[str, list[str]] = {}
    for aid in sorted(runs):
        if not any(runs[aid].values()):
            continue
        leak = (meta[aid].get("TARGETS_LEAK") or "").upper() or ATTACK_TO_LEAK.get(aid, "") or "SWEEP"
        groups.setdefault(leak, []).append(aid)

    rows = []
    for leak in sorted(groups, key=lambda k: (k == "SWEEP", k)):
        aids = groups[leak]
        still_open = any(runs[a][max(runs[a])] for a in aids)
        if leak == "SWEEP":
            title, fix = "SSN sweep found copies nobody listed", "Closed with the same fixes: SSN mask + SCRATCH revoked."
            tags = "HIPAA minimum necessary"
        else:
            title, fix = LEAK_SHORT.get(leak, leak), FIX_PLAIN.get(leak, "")
            tags = "; ".join(LEAK_TAGS.get(leak, []))
        sqls = sorted({(fix_by[a].get("SQL_APPLIED") or "").strip() for a in aids if a in fix_by} - {""})
        sql_html = (f'<details><summary>SQL</summary><pre>{e(chr(10).join(sqls))}</pre></details>' if sqls else "")
        who = ", ".join(f'{a}{"*" if meta[a].get("SOURCE") == "gemma" else ""}' for a in aids)
        status = '<span class="st open">Open</span>' if still_open else '<span class="st ok">Fixed &amp; re-checked</span>'
        rows.append(f"<tr><td><div class='t'>{e(title)}</div><div class='m'>{e(tags)}</div></td>"
                    f"<td class='m'>{e(who)}</td><td>{e(fix)}{sql_html}</td><td>{status}</td></tr>")
    findings = "".join(rows) or "<tr><td colspan='4' class='m'>No leaks found yet.</td></tr>"

    b = d.get("bouncer", [])
    b_block = [x for x in b if x.get("VERDICT") == "BLOCK"]
    fw = d.get("firewall", [])
    fw_block, fw_pass = sum(1 for x in fw if x.get("VERDICT") == "BLOCK"), sum(1 for x in fw if x.get("VERDICT") == "PASS")
    b_rows = "".join(f"<tr><td><code>{e(x['PACKAGE'])}</code></td><td>{e(x['VERDICT'])}</td><td class='m'>{e((x.get('REASONS') or '').split(';')[0])}</td></tr>" for x in b[:8])
    fw_rows = "".join(f"<tr><td><code>{e(x['CHANGE_ID'])}</code></td><td>{e(x['VERDICT'])}{' · merged' if x.get('MERGED') else ''}</td><td class='m'>{e(_findings_kind(x.get('FINDINGS')))}</td></tr>" for x in fw[:8])

    rounds = "".join(f"<li><b>Round {r['ROUND_NO']}</b> {int(r['LEAKS'] or 0)} of {int(r['ATTACKS'] or 0)} attacks leaked · "
                     f"legit {int(r['LEGIT_PASSED'] or 0)}/{int(r['LEGIT_TOTAL'] or 0)}</li>" for r in board)
    n_gemma = sum(1 for a in groups.values() for x in a if meta[x].get("SOURCE") == "gemma")

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>LeakHunter Results</title>
<style>
:root{{--bg:#fafaf9;--card:#ffffff;--ink:#1c1c1a;--m:#6a6a64;--line:#e7e6e1;--accent:#1f4e8c;--ok:#1d6b45;--okbg:#e8f3ec;--bad:#a8261b;--badbg:#fbeceb}}
@media (prefers-color-scheme:dark){{:root{{--bg:#141413;--card:#1c1c1b;--ink:#ebeae5;--m:#a09f98;--line:#2f2e2b;--accent:#8fb3e8;--ok:#6ccf98;--okbg:#16301f;--bad:#ff8f80;--badbg:#381a16}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}}
main{{max-width:980px;margin:0 auto;padding:40px 16px 64px}}
.k{{font-size:13px;letter-spacing:.06em;text-transform:uppercase;color:var(--m);margin:0 0 6px}}
h1{{font-size:30px;line-height:1.2;margin:0 0 8px;font-weight:700}}.lead{{color:var(--m);max-width:680px;margin:0}}
h2{{font-size:19px;margin:0 0 4px}}.sub{{color:var(--m);margin:0 0 16px;font-size:15px}}
section{{margin-top:40px}}
.hero{{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:1px;background:var(--line);border:1px solid var(--line);border-radius:12px;overflow:hidden;margin-top:28px}}
.hero div{{background:var(--card);padding:22px}}.n{{font-size:36px;font-weight:700;line-height:1.1}}.n small{{font-size:20px;color:var(--m);font-weight:600}}
.hero p{{margin:6px 0 0;color:var(--m);font-size:14px}}
.steps{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px}}
.step{{border-top:2px solid var(--accent);padding-top:12px}}.step b{{display:block;margin-bottom:4px}}.step p{{margin:0;color:var(--m);font-size:15px}}
.tbl{{background:var(--card);border:1px solid var(--line);border-radius:12px;overflow-x:auto}}
table{{width:100%;border-collapse:collapse;font-size:15px}}th,td{{text-align:left;padding:12px 14px;border-top:1px solid var(--line);vertical-align:top}}
th{{border-top:0;font-size:13px;color:var(--m);font-weight:600}}.t{{font-weight:600}}.m{{color:var(--m);font-size:13px}}
.st{{display:inline-block;padding:2px 10px;border-radius:999px;font-size:13px;font-weight:600;white-space:nowrap}}
.st.ok{{background:var(--okbg);color:var(--ok)}}.st.open{{background:var(--badbg);color:var(--bad)}}
details{{margin-top:6px}}summary{{cursor:pointer;color:var(--accent);font-size:13px}}
pre,code{{font:12.5px/1.45 ui-monospace,Consolas,monospace}}pre{{white-space:pre-wrap;word-break:break-word;color:var(--m);margin:6px 0 0}}
ul.r{{list-style:none;padding:0;margin:0}}ul.r li{{padding:6px 0;border-bottom:1px solid var(--line)}}
.more>summary{{font-size:16px;color:var(--ink);font-weight:600;padding:14px 0}}.more .tbl{{margin-bottom:16px}}
footer{{margin-top:48px;color:var(--m);font-size:13px;border-top:1px solid var(--line);padding-top:16px}}
</style></head><body><main>
<p class="k">LeakHunter · leak audit · Snowflake</p>
<h1>Every leak we could prove was fixed, and every fix was proven to hold.</h1>
<p class="lead">LeakHunter attacks a data warehouse the way a real insider would, fixes what it proves, and re-checks that the fixes hold without breaking legitimate work. This run: synthetic hospital and HR data · snapshot {e(d.get('generated_at'))}.</p>

<div class="hero">
<div><div class="n">{leaks0} <small>&rarr;</small> {leaks1}</div><p>leaks found, then left after the fixes</p></div>
<div><div class="n">{lp}<small>/{lt}</small></div><p>legitimate analyst queries still work</p></div>
<div><div class="n">{'—' if reid is None else reid}<small> / 2,000</small></div><p>&ldquo;anonymous&rdquo; patients re-identified with free Census data, before the fix</p></div>
</div>

<section><h2>How it works</h2><p class="sub">Three steps, run as many rounds as you like.</p>
<div class="steps">
<div class="step"><b>1 · Attack</b><p>A hand-written attack library plus attacks written by Gemma (an open model, run locally) query the warehouse as the analyst role.</p></div>
<div class="step"><b>2 · Fix</b><p>The open pii-guardian skill maps each proven leak to the smallest Snowflake-native fix: a masking policy, a revoked grant, or a dropped copy.</p></div>
<div class="step"><b>3 · Prove</b><p>The referee re-runs every attack and ten legitimate analyst queries. Success means leaks at zero and nothing legitimate broken.</p></div>
</div></section>

<section><h2>What leaked, and how it was fixed</h2><p class="sub">Grouped by root cause. * = attack written by Gemma.</p>
<div class="tbl"><table><tr><th>Leak</th><th>Caught by</th><th>Fix</th><th>Status</th></tr>{findings}</table></div></section>

<section><h2>Rounds</h2><ul class="r">{rounds}</ul></section>

<section><h2>Plugging it into your data platform</h2><p class="sub">Built to run continuously against a real warehouse, not just this dataset.</p>
<div class="steps">
<div class="step"><b>Connect</b><p>Two roles: a low-privilege role to attack as, and an admin role to fix and log. Key-pair auth, no passwords.</p></div>
<div class="step"><b>Schedule</b><p>Run a round after every schema change, grant, or on a timer. Every attack, fix and re-check is stored as an audit trail.</p></div>
<div class="step"><b>Fix your way</b><p>The pii-guardian and Bouncer skills follow the open Agent Skills standard, so any agent or a plain script can apply the same playbook.</p></div>
<div class="step"><b>Extend</b><p>Attacks and legitimate checks are plain YAML. Snowflake today; the attack, fix and prove loop is designed for other warehouses next.</p></div>
</div></section>

<section><details class="more"><summary>Guarding the door for AI agents: {len(b_block)} packages blocked · {fw_block} risky changes blocked, {fw_pass} passed</summary>
<p class="sub"><b>Bouncer</b> checks every package an AI agent wants to install (invented names, look-alikes, brand-new releases).</p>
<div class="tbl"><table><tr><th>Package</th><th>Verdict</th><th>Main reason</th></tr>{b_rows or "<tr><td colspan='3' class='m'>No checks yet.</td></tr>"}</table></div>
<p class="sub"><b>Change Firewall</b> applies an agent's proposed change to a zero-copy clone, attacks the clone, and only allows it if nothing leaks.</p>
<div class="tbl"><table><tr><th>Change</th><th>Verdict</th><th>Main finding</th></tr>{fw_rows or "<tr><td colspan='3' class='m'>No changes yet.</td></tr>"}</table></div>
</details></section>

<footer>All data is synthetic (SSNs start with 9, never issued). Attack sample rows are deliberately not shown. Regulation tags
are pointers for a reviewer, not legal advice. Open source (MIT): github.com/Manavpatel06/Leak_Hunter</footer>
</main></body></html>"""


def main() -> None:
    data = fetch()
    OUT_JSON.write_text(json.dumps(data, indent=1, default=str), encoding="utf-8")
    OUT_HTML.write_text(build_html(data), encoding="utf-8")
    b = data["scoreboard"]
    print(f"OK: wrote {OUT_HTML} and {OUT_JSON} ({len(b)} rounds). Open {OUT_HTML} in a browser.")


if __name__ == "__main__":
    main()
