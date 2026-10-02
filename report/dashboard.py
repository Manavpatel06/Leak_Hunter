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
def e(v) -> str:
    return html.escape("" if v is None else str(v))


def chip(text: str, kind: str) -> str:
    return f'<span class="chip {kind}">{e(text)}</span>'


def bars(board: list[dict]) -> str:
    if not board:
        return '<p class="muted">No rounds yet.</p>'
    w, h, pad = 560, 180, 28
    top = max([int(r["ATTACKS"] or 0) for r in board] + [1])
    n = len(board)
    bw = min(56, (w - pad * 2) / n * 0.6)
    out = [f'<svg viewBox="0 0 {w} {h + 60}" role="img" aria-label="Leaks per round">']
    for i, r in enumerate(board):
        x = pad + (i + 0.5) * (w - pad * 2) / n - bw / 2
        att, leaks = int(r["ATTACKS"] or 0), int(r["LEAKS"] or 0)
        ha, hl = h * att / top, h * leaks / top
        out.append(f'<rect x="{x:.1f}" y="{h - ha + 24:.1f}" width="{bw:.1f}" height="{ha:.1f}" rx="4" class="bar-all"/>')
        if leaks:
            out.append(f'<rect x="{x:.1f}" y="{h - hl + 24:.1f}" width="{bw:.1f}" height="{hl:.1f}" rx="4" class="bar-leak"/>')
        out.append(f'<text x="{x + bw / 2:.1f}" y="{h - ha + 18:.1f}" class="lbl">{leaks}/{att}</text>')
        out.append(f'<text x="{x + bw / 2:.1f}" y="{h + 44}" class="axis">Round {r["ROUND_NO"]}</text>')
    out.append("</svg>")
    return "".join(out)


def build_html(d: dict) -> str:
    board, attacks, fixes = d["scoreboard"], d["attacks"], d["fixes"]
    first, last = (board[0], board[-1]) if board else ({}, {})
    reid = d["reidentified"][0]["N"] if d.get("reidentified") else None
    blocks = sum(1 for b in d.get("bouncer", []) if b.get("VERDICT") == "BLOCK")

    runs: dict[str, dict[int, bool]] = {}
    meta: dict[str, dict] = {}
    for a in attacks:
        r = runs.setdefault(a["ATTACK_ID"], {})
        r[int(a["ROUND_NO"])] = r.get(int(a["ROUND_NO"]), False) or bool(a["SUCCEEDED"])
        meta.setdefault(a["ATTACK_ID"], a)
    fix_by = {}
    for f in fixes:
        fix_by.setdefault(f["ATTACK_ID"], f)
    found = [k for k in sorted(runs) if any(runs[k].values())]

    def kpi(label, value, sub, kind=""):
        return f'<div class="kpi {kind}"><div class="kl">{e(label)}</div><div class="kv">{value}</div><div class="ks">{e(sub)}</div></div>'

    leaks_now = int(last.get("LEAKS") or 0)
    legit_ok = (last.get("LEGIT_PASSED") or 0) == (last.get("LEGIT_TOTAL") or 0) and last.get("LEGIT_TOTAL")
    kpis = "".join([
        kpi("Leaks", f'{first.get("LEAKS", 0) or 0} → {leaks_now}', f'round {first.get("ROUND_NO", "-")} → round {last.get("ROUND_NO", "-")}',
            "good" if board and leaks_now == 0 else "bad"),
        kpi("Legit queries", f'{last.get("LEGIT_PASSED", 0) or 0}/{last.get("LEGIT_TOTAL", 0) or 0}',
            "nothing legitimate broken" if legit_ok else "check legit failures", "good" if legit_ok else "bad"),
        kpi("Re-identified", "—" if reid is None else f"{reid}", "patients re-identifiable via free Census data when unmasked", "warn"),
        kpi("Bouncer blocks", f"{blocks}", "bad packages stopped at the door", ""),
    ])

    rows = []
    for aid in found:
        m = meta[aid]
        leak = (m.get("TARGETS_LEAK") or "").upper() or ATTACK_TO_LEAK.get(aid, "")
        what = LEAK_TEXT.get(leak) or m.get("GOAL") or ""
        f = fix_by.get(aid)
        fix = (f"{e(f['FIX_TYPE'])} · {e(f['APPLIED_BY'])}<code>{e((f.get('SQL_APPLIED') or '').splitlines()[0] if f.get('SQL_APPLIED') else '')}</code>"
               if f else '<span class="muted">none</span>')
        last_r = max(runs[aid])
        status = chip("still open", "bad") if runs[aid][last_r] else (
            chip(f"closed · proven r{last_r}", "good") if last_r > min(r for r, ok in runs[aid].items() if ok)
            else chip("not re-checked", "warn"))
        src = f' <span class="muted">{e(m.get("SOURCE"))}</span>' if m.get("SOURCE") not in (None, "library") else ""
        rows.append(f"<tr><td><b>{e(aid)}</b>{src}<div class='muted'>{e(leak)}</div></td><td>{e(what)}"
                    f"<div class='tags'>{e('; '.join(_tags(leak, m.get('TECHNIQUE') or '', m.get('GOAL') or '')))}</div></td>"
                    f"<td>{fix}</td><td>{status}</td></tr>")
    findings = "".join(rows) or '<tr><td colspan="4" class="muted">No leaks found yet.</td></tr>'

    last_round = int(last.get("ROUND_NO") or 0)
    rejected = [a for a in attacks if int(a["ROUND_NO"]) == last_round and not a["SUCCEEDED"]]
    rej_rows = "".join(
        f"<tr><td><b>{e(a['ATTACK_ID'])}</b></td><td>{e(a.get('GOAL'))}</td>"
        f"<td>{e((a.get('ERROR') or '').split(':')[0][:60] or 'blocked by masking / no rows')}</td></tr>"
        for a in rejected) or '<tr><td colspan="3" class="muted">None.</td></tr>'

    legit_last = [q for q in d.get("legit", []) if int(q["ROUND_NO"]) == last_round]
    legit_rows = "".join(f"<tr><td>{e(q['QUERY_ID'])}</td><td>{e(q.get('DESCRIPTION'))}</td>"
                         f"<td>{chip('pass', 'good') if q['PASSED'] else chip('fail', 'bad')}</td></tr>"
                         for q in legit_last) or '<tr><td colspan="3" class="muted">No legit runs yet.</td></tr>'

    vk = {"BLOCK": "bad", "WARN": "warn", "ALLOW": "good", "PASS": "good", "ERROR": "bad"}
    bouncer_rows = "".join(f"<tr><td><code>{e(b['PACKAGE'])}</code></td><td>{chip(b['VERDICT'], vk.get(b['VERDICT'], ''))}</td>"
                           f"<td>{e(b.get('REASONS'))}</td><td>{e(b.get('REQUESTED_BY'))}</td></tr>"
                           for b in d.get("bouncer", [])) or '<tr><td colspan="4" class="muted">No checks yet.</td></tr>'
    fw_rows = "".join(f"<tr><td><code>{e(c['CHANGE_ID'])}</code></td><td>{e(c.get('SUBMITTED_BY'))}</td>"
                      f"<td>{chip(c['VERDICT'], vk.get(c['VERDICT'], ''))}{' · merged' if c.get('MERGED') else ''}</td>"
                      f"<td>{e(c.get('FINDINGS'))}</td></tr>"
                      for c in d.get("firewall", [])) or '<tr><td colspan="4" class="muted">No changes submitted yet.</td></tr>'

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>LeakHunter Results</title>
<style>
:root{{--bg:#f7f7f5;--card:#fff;--ink:#1d1d1b;--muted:#6b6b66;--line:#e4e3de;--good:#1f7a4d;--goodbg:#e3f3ea;
--bad:#b42318;--badbg:#fdecea;--warn:#8a5a00;--warnbg:#fdf3dc;--accent:#2f5bd3;--barall:#d7d6d0}}
@media (prefers-color-scheme:dark){{:root{{--bg:#151514;--card:#1f1f1d;--ink:#ecebe6;--muted:#a3a29b;--line:#34332f;
--good:#5cc98f;--goodbg:#173324;--bad:#ff8a7a;--badbg:#3a1b17;--warn:#f0c060;--warnbg:#3a2e12;--accent:#8aa8ff;--barall:#3a3935}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}}
main{{max-width:1100px;margin:0 auto;padding:28px 16px 60px}}h1{{font-size:28px;margin:0}}h2{{font-size:17px;margin:0 0 12px}}
.sub{{color:var(--muted);margin:4px 0 22px}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin-bottom:16px}}
.kpi,.card{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}}
.kl{{color:var(--muted);font-size:13px}}.kv{{font-size:30px;font-weight:700;margin:2px 0}}.ks{{color:var(--muted);font-size:13px}}
.kpi.good .kv{{color:var(--good)}}.kpi.bad .kv{{color:var(--bad)}}.kpi.warn .kv{{color:var(--warn)}}
.card{{margin-bottom:16px;overflow-x:auto}}table{{width:100%;border-collapse:collapse;font-size:14px}}
th,td{{text-align:left;padding:8px 10px;border-top:1px solid var(--line);vertical-align:top}}th{{color:var(--muted);font-weight:600;border-top:0}}
code{{display:block;font:12px/1.4 ui-monospace,Consolas,monospace;color:var(--muted);margin-top:4px;word-break:break-word}}
.muted{{color:var(--muted)}}.tags{{color:var(--muted);font-size:12px;margin-top:4px}}
.chip{{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}}
.chip.good{{background:var(--goodbg);color:var(--good)}}.chip.bad{{background:var(--badbg);color:var(--bad)}}.chip.warn{{background:var(--warnbg);color:var(--warn)}}
svg{{width:100%;max-width:640px;height:auto}}.bar-all{{fill:var(--barall)}}.bar-leak{{fill:var(--bad)}}
.lbl{{fill:var(--ink);font-size:12px;text-anchor:middle;font-weight:600}}.axis{{fill:var(--muted);font-size:12px;text-anchor:middle}}
.two{{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px}}.two .card{{margin:0}}
footer{{color:var(--muted);font-size:13px;margin-top:20px}}
</style></head><body><main>
<h1>LeakHunter</h1>
<p class="sub">One AI attacks the Snowflake warehouse, the defender fixes every proven leak, the referee proves the fixes hold
without breaking legitimate work. Snapshot {e(d.get('generated_at'))} · all data synthetic.</p>
<div class="grid">{kpis}</div>
<div class="two">
<div class="card"><h2>Leaks per round</h2>{bars(board)}<p class="muted" style="margin:6px 0 0">Red = attacks that leaked · grey = attacks tried.</p></div>
<div class="card"><h2>Legitimate analyst queries (latest round)</h2><table><tr><th>ID</th><th>Query</th><th></th></tr>{legit_rows}</table></div>
</div>
<div class="card" style="margin-top:16px"><h2>Findings: every leak, the rule it breaks, the fix, the proof</h2>
<table><tr><th>Attack</th><th>What leaked</th><th>Fix applied</th><th>Re-check</th></tr>{findings}</table></div>
<div class="card"><h2>Rejected: what the attacker tried in the latest round that did not work</h2>
<table><tr><th>Attack</th><th>Goal</th><th>Why it failed</th></tr>{rej_rows}</table></div>
<div class="two">
<div class="card"><h2>Bouncer: packages AI agents asked to install</h2><table><tr><th>Package</th><th>Verdict</th><th>Why</th><th>By</th></tr>{bouncer_rows}</table></div>
<div class="card"><h2>Change Firewall: changes tested on a clone first</h2><table><tr><th>Change</th><th>By</th><th>Verdict</th><th>Findings</th></tr>{fw_rows}</table></div>
</div>
<footer>Attacks and legitimate queries run as the low-privilege <b>LH_ANALYST</b> role (secondary roles off). Fixes are Snowflake-native:
masking policies, revoked grants, dropped scratch copies. Sample rows from attacks are deliberately left out. Regulation tags are
pointers for a reviewer, not legal advice. Open source (MIT): pii-guardian + bouncer Agent Skills, Gemma attacker.</footer>
</main></body></html>"""


def main() -> None:
    data = fetch()
    OUT_JSON.write_text(json.dumps(data, indent=1, default=str), encoding="utf-8")
    OUT_HTML.write_text(build_html(data), encoding="utf-8")
    b = data["scoreboard"]
    print(f"OK: wrote {OUT_HTML} and {OUT_JSON} ({len(b)} rounds). Open {OUT_HTML} in a browser.")


if __name__ == "__main__":
    main()
