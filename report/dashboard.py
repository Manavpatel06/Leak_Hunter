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
OUT_DIR = Path("site")
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
# Product view of one scan cycle. Severity / asset / remediation per root cause (CONTRACTS §5).
FINDING = {
    "L1": ("Critical", "Patient SSNs readable in clear text", "DATA.PATIENTS.SSN",
           "Masking policy MASK_SSN on the column. Analysts see ***-**-1234."),
    "L3": ("Critical", "“Anonymized” patients re-identifiable with public Census data", "DATA.PATIENT_DEMOGRAPHICS",
           "ZIP generalized to 3 digits, birth date to year (MASK_ZIP, MASK_DOB). The Census join matches no one."),
    "L5": ("High", "Forgotten raw export of patient records", "SCRATCH.PATIENTS_EXPORT_OLD",
           "Analyst access to SCRATCH revoked; stale copy dropped."),
    "L6": ("High", "Patient names joined to diagnoses", "DATA.VISIT_DETAILS",
           "Masking policy MASK_NAME on patient names. Diagnoses stay usable."),
    "L2": ("High", "Salaries readable next to employee names", "DATA.EMPLOYEES.FULL_NAME",
           "Masking policy MASK_NAME on employee names. Salary averages still work."),
    "SWEEP": ("High", "SSN columns found outside the known inventory", "All analyst-readable tables",
              "Closed by the SSN mask and the SCRATCH revoke above."),
    "L4": ("Medium", "HR performance reviews reachable through a role grant", "Role LH_HR → LH_ANALYST",
           "Role grant revoked (least privilege)."),
}
SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2}


def e(v) -> str:
    return html.escape("" if v is None else str(v))


def _kind(raw) -> str:
    import re
    m = re.search(r'"kind":\s*"([a-z_]+)"', raw or "")
    if m:
        return m.group(1).replace("_", " ")
    return "no leak found on the clone" if '"findings": []' in (raw or "") else "see audit trail"


def build_html(d: dict) -> str:
    board, attacks, fixes = d["scoreboard"], d["attacks"], d["fixes"]
    first, last = (board[0], board[-1]) if board else ({}, {})
    reid = d["reidentified"][0]["N"] if d.get("reidentified") else 0
    found, open_now = int(first.get("LEAKS") or 0), int(last.get("LEAKS") or 0)
    lp, lt = int(last.get("LEGIT_PASSED") or 0), int(last.get("LEGIT_TOTAL") or 0)
    n_attacks = int(last.get("ATTACKS") or 0)

    runs: dict[str, dict[int, bool]] = {}
    meta: dict[str, dict] = {}
    for a in attacks:
        r = runs.setdefault(a["ATTACK_ID"], {})
        r[int(a["ROUND_NO"])] = r.get(int(a["ROUND_NO"]), False) or bool(a["SUCCEEDED"])
        meta.setdefault(a["ATTACK_ID"], a)
    fix_by = {f["ATTACK_ID"]: f for f in fixes}
    groups: dict[str, list[str]] = {}
    for aid in sorted(runs):
        if any(runs[aid].values()):
            leak = (meta[aid].get("TARGETS_LEAK") or "").upper() or ATTACK_TO_LEAK.get(aid, "") or "SWEEP"
            groups.setdefault(leak, []).append(aid)

    items = []
    for leak in sorted(groups, key=lambda k: (SEV_ORDER[FINDING.get(k, ("High",))[0]], k)):
        aids = groups[leak]
        sev, title, asset, fix = FINDING.get(leak, ("High", leak, "", ""))
        is_open = any(runs[a][max(runs[a])] for a in aids)
        sqls = sorted({(fix_by[a].get("SQL_APPLIED") or "").strip() for a in aids if a in fix_by} - {""})
        tags = "; ".join(LEAK_TAGS.get(leak, ["HIPAA Privacy Rule (minimum necessary)"]))
        det = ", ".join(f'{a} ({"Gemma" if meta[a].get("SOURCE") == "gemma" else "library"})' for a in aids)
        status = '<span class="pill red">Open</span>' if is_open else '<span class="pill green">Verified fixed</span>'
        items.append(f"""<details class="f"><summary>
<span class="sev {sev.lower()}">{sev}</span><span class="ft">{e(title)}</span><span class="asset">{e(asset)}</span>{status}</summary>
<div class="fd"><dl>
<dt>Detected by</dt><dd>{e(det)}</dd>
<dt>Policy</dt><dd>{e(tags)}</dd>
<dt>Remediation</dt><dd>{e(fix)}</dd>
<dt>Verification</dt><dd>{"Still reachable in the latest scan." if is_open else f"Attack re-run in scan #{last.get('ROUND_NO')}: blocked."}</dd>
</dl>{f'<pre>{e(chr(10).join(sqls))}</pre>' if sqls else ''}</div></details>""")
    findings = "".join(items) or '<p class="muted">No findings.</p>'
    crit = sum(1 for k in groups if FINDING.get(k, ("High",))[0] == "Critical")

    b, seen = [], set()
    for x in d.get("bouncer", []):          # latest verdict per package
        if x.get("PACKAGE") not in seen:
            seen.add(x.get("PACKAGE"))
            b.append(x)
    fw = d.get("firewall", [])
    b_block = sum(1 for x in b if x.get("VERDICT") == "BLOCK")
    fw_block = sum(1 for x in fw if x.get("VERDICT") == "BLOCK")
    fw_pass = sum(1 for x in fw if x.get("VERDICT") == "PASS")
    vcls = {"BLOCK": "red", "WARN": "amber", "ALLOW": "green", "PASS": "green", "ERROR": "red"}
    b_rows = "".join(f'<tr><td><code>{e(x["PACKAGE"])}</code></td><td><span class="pill {vcls.get(x["VERDICT"], "")}">{e(x["VERDICT"].title())}</span></td><td class="muted">{e((x.get("REASONS") or "").split(";")[0])}</td></tr>' for x in b[:6])
    fw_rows = "".join(f'<tr><td><code>{e(x["CHANGE_ID"])}</code></td><td><span class="pill {vcls.get(x["VERDICT"], "")}">{e(x["VERDICT"].title())}</span></td><td class="muted">{e(_kind(x.get("FINDINGS")))}</td></tr>' for x in fw[:6])

    scans = []
    for i, r in enumerate(board):
        lk = int(r["LEAKS"] or 0)
        scans.append(f'<li><div class="dot {"red" if lk else "green"}"></div><div><b>Scan #{r["ROUND_NO"]}</b>'
                     f'<span class="muted"> · {int(r["ATTACKS"] or 0)} attacks · legit {int(r["LEGIT_PASSED"] or 0)}/{int(r["LEGIT_TOTAL"] or 0)}</span>'
                     f'<div>{lk} leak{"s" if lk != 1 else ""} proven</div></div></li>')
        if i < len(board) - 1:
            nfix = sum(1 for f in fixes if int(f["ROUND_NO"]) == int(r["ROUND_NO"]))
            scans.append(f'<li><div class="dot blue"></div><div><b>Remediation</b><span class="muted"> · pii-guardian playbook</span>'
                         f'<div>{nfix} fixes applied and logged</div></div></li>')
    posture = "Protected" if board and open_now == 0 else ("At risk" if board else "Not scanned")

    legit_last = [q for q in d.get("legit", []) if int(q["ROUND_NO"]) == int(last.get("ROUND_NO") or 0)]
    PASS, FAIL = '<span class="pill green">Pass</span>', '<span class="pill red">Fail</span>'
    legit_rows = "".join(f'<tr><td><code>{e(q["QUERY_ID"])}</code></td><td>{e(q.get("DESCRIPTION"))}</td>'
                         f'<td>{PASS if q["PASSED"] else FAIL}</td></tr>' for q in legit_last)

    def _leak_pill(n: int) -> str:
        return f'<span class="pill {"red" if n else "green"}">{n}</span>'
    round_rows = "".join(f'<tr><td><b>#{r["ROUND_NO"]}</b></td><td>{int(r["ATTACKS"] or 0)}</td>'
                         f'<td>{_leak_pill(int(r["LEAKS"] or 0))}</td>'
                         f'<td>{int(r["LEGIT_PASSED"] or 0)}/{int(r["LEGIT_TOTAL"] or 0)}</td></tr>' for r in board)
    sev_counts = {k: sum(1 for g in groups if FINDING.get(g, ("High",))[0] == k) for k in ("Critical", "High", "Medium")}
    ctx = dict(posture=posture, open_now=open_now, found=found, crit=crit, lp=lp, lt=lt, reid=reid,
               findings=findings, n_groups=len(groups), scans="".join(scans), n_attacks=n_attacks,
               b_block=b_block, fw_block=fw_block, fw_pass=fw_pass, b_rows=b_rows, fw_rows=fw_rows,
               legit_rows=legit_rows, round_rows=round_rows, sev=sev_counts, when=e(d.get("generated_at")),
               n_fixes=len(fixes))
    return render_site(ctx)


CSS = """
:root{--bg:#f4f2ed;--panel:#fffdf9;--ink:#16181b;--muted:#5f6368;--line:#e2ded5;--brand:#d9480f;--brandbg:#fbe9df;
--green:#1e7a46;--greenbg:#e3f1e7;--red:#b42318;--redbg:#fbe7e4;--amber:#8a5300;--amberbg:#f9edd6;--side:#16181b}
@media (prefers-color-scheme:dark){:root{--bg:#111214;--panel:#191a1d;--ink:#ecebe7;--muted:#9c9c97;--line:#2a2b2f;--brand:#ff7a3d;--brandbg:#33200f;
--green:#62cf8f;--greenbg:#14281c;--red:#ff8a78;--redbg:#36170f;--amber:#f0bd5a;--amberbg:#34270e;--side:#0c0d0e}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 Inter,system-ui,-apple-system,"Segoe UI",sans-serif}
a{color:inherit;text-decoration:none}code,pre{font:12.5px/1.5 ui-monospace,"Cascadia Code",Consolas,monospace}
.app{display:grid;grid-template-columns:220px 1fr;min-height:100vh}
aside{background:var(--side);color:#e9e7e1;border-right:1px solid #000;padding:18px 14px;position:sticky;top:0;height:100vh}
.logo{display:flex;align-items:center;gap:10px;font-weight:700;font-size:16px;margin:2px 6px 22px}
.mark{width:26px;height:26px;border-radius:4px;background:var(--brand);display:grid;place-items:center}
.mark i{width:10px;height:10px;border:2.5px solid #fff;border-radius:50%}
nav a{display:block;padding:8px 10px;border-radius:6px;color:#a7a59f;font-weight:500;border-left:2px solid transparent}nav a:hover{color:#fff;background:#23252a}
nav a.on{color:#fff;background:#23252a;border-left-color:var(--brand)}
.side-foot{position:absolute;bottom:18px;left:14px;right:14px;font-size:12px;color:#8d8b85;padding:0 6px}.tag{font-size:11px;color:#8d8b85;font-weight:500;letter-spacing:.02em;margin:-16px 6px 22px}
header{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;padding:16px 32px;border-bottom:1px solid var(--line);background:var(--panel)}
.ws{display:flex;align-items:center;gap:10px;font-weight:600}.ws .muted{font-weight:400}
.live{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 0 3px var(--greenbg)}
main{padding:28px 32px 56px;max-width:1180px}h1{font-size:22px;margin:0 0 4px}h2{font-size:15px;margin:0 0 12px}
.muted{color:var(--muted)}section{margin-top:28px;scroll-margin-top:16px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:18px 20px}
.cards{display:grid;grid-template-columns:1.3fr 1fr 1fr;gap:14px}
.lab{font-size:12px;color:var(--muted);font-weight:500;text-transform:uppercase;letter-spacing:.05em}
.big{font-size:30px;font-weight:700;margin:6px 0 2px;letter-spacing:-.02em;font-variant-numeric:tabular-nums}.big small{font-size:16px;color:var(--muted);font-weight:500}
.status{display:flex;align-items:center;gap:10px}.status .big{color:var(--green)}.status.risk .big{color:var(--red)}
.shield{width:34px;height:34px;border-radius:10px;background:var(--greenbg);display:grid;place-items:center;color:var(--green);font-weight:800}
.risk .shield{background:var(--redbg);color:var(--red)}
.pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap;background:var(--line)}
.pill.green{background:var(--greenbg);color:var(--green)}.pill.red{background:var(--redbg);color:var(--red)}.pill.amber{background:var(--amberbg);color:var(--amber)}
.grid2{display:grid;grid-template-columns:2fr 1fr;gap:14px}
.f{border-top:1px solid var(--line)}.f:first-of-type{border-top:0}
.f summary{list-style:none;cursor:pointer;display:grid;grid-template-columns:78px 1fr 230px 110px;gap:12px;align-items:center;padding:13px 4px}
.f summary::-webkit-details-marker{display:none}.f summary:hover{background:var(--bg)}
.ft{font-weight:600}.asset{color:var(--muted);font:12px ui-monospace,Consolas,monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sev{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:3px 8px;border-radius:6px;text-align:center}
.sev.critical{background:var(--redbg);color:var(--red)}.sev.high{background:var(--amberbg);color:var(--amber)}.sev.medium{background:var(--brandbg);color:var(--brand)}
.fd{padding:2px 4px 16px 94px}dl{display:grid;grid-template-columns:110px 1fr;gap:6px 14px;margin:0}dt{color:var(--muted)}dd{margin:0}
pre{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px 12px;margin:12px 0 0;white-space:pre-wrap;word-break:break-word;color:var(--muted)}
.tl{list-style:none;margin:0;padding:0}.tl li{display:flex;gap:12px;padding:0 0 16px;position:relative}
.tl li:not(:last-child)::before{content:"";position:absolute;left:5px;top:16px;bottom:0;width:2px;background:var(--line)}
.dot{width:12px;height:12px;border-radius:50%;margin-top:4px;flex:none}.dot.red{background:var(--red)}.dot.green{background:var(--green)}.dot.blue{background:var(--brand)}
table{width:100%;border-collapse:collapse}td,th{padding:9px 6px;border-top:1px solid var(--line);text-align:left;vertical-align:top}th{border-top:0;color:var(--muted);font-weight:500;font-size:12px}
.ints{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}.int{display:flex;justify-content:space-between;align-items:center}
@media (max-width:900px){.app{grid-template-columns:1fr}aside{display:none}.cards,.grid2{grid-template-columns:1fr}
.f summary{grid-template-columns:70px 1fr}.asset,.f summary .pill{display:none}.fd{padding-left:4px}main,header{padding-left:16px;padding-right:16px}}

.crumb{color:var(--muted);font-size:13px;margin-bottom:6px}.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.btn{display:inline-block;padding:10px 16px;border-radius:6px;font-weight:600;border:1px solid var(--line);background:var(--panel)}
.btn.primary{background:var(--brand);border-color:var(--brand);color:#fff}.btn:hover{filter:brightness(.97)}
.more{display:inline-block;margin-top:12px;color:var(--brand);font-weight:600}
.sevbar{display:flex;gap:8px;margin:0 0 14px}
/* landing */
.lp{max-width:1120px;margin:0 auto;padding:0 24px}.top{display:flex;align-items:center;justify-content:space-between;padding:20px 0}
.top nav{display:flex;gap:22px;align-items:center}.top nav a{color:var(--muted);font-weight:500}.top nav a:hover{color:var(--ink)}
.brandrow{display:flex;align-items:center;gap:10px;font-weight:700;font-size:17px}
.hero{padding:72px 0 56px;display:grid;grid-template-columns:1.15fr .85fr;gap:48px;align-items:center}
.eyebrow{display:inline-block;font-size:12px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--brand);margin-bottom:14px}
.hero h1{font-size:52px;line-height:1.05;letter-spacing:-.03em;margin:0 0 18px}.hero p{font-size:18px;color:var(--muted);margin:0 0 28px;max-width:540px}
.proof{background:var(--side);color:#ecebe7;border-radius:10px;padding:24px}
.proof .pr{display:flex;justify-content:space-between;align-items:baseline;padding:14px 0;border-bottom:1px solid #2a2b2f}
.proof .pr:last-child{border-bottom:0}.proof b{font-size:30px;font-variant-numeric:tabular-nums}.proof span{color:#a7a59f;font-size:14px;max-width:60%}
.proof .k{color:var(--brand);font-size:12px;font-weight:700;letter-spacing:.08em;text-transform:uppercase}
.band{border-top:1px solid var(--line);padding:56px 0}.band h2{font-size:28px;letter-spacing:-.02em;margin:0 0 8px}
.cols{display:grid;grid-template-columns:repeat(3,1fr);gap:28px;margin-top:28px}.cols h3{margin:10px 0 6px;font-size:17px}.cols p{margin:0;color:var(--muted)}
.num{font:700 13px ui-monospace,Consolas,monospace;color:var(--brand)}
.feat{display:grid;grid-template-columns:repeat(2,1fr);gap:16px;margin-top:28px}
.cta{background:var(--side);color:#ecebe7;border-radius:10px;padding:40px;display:flex;justify-content:space-between;align-items:center;gap:20px;flex-wrap:wrap}
.cta h2{color:#fff}.cta p{color:#a7a59f;margin:0}
.foot{padding:28px 0 40px;color:var(--muted);font-size:13px;display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px}
@media (max-width:900px){.hero{grid-template-columns:1fr;padding-top:40px}.hero h1{font-size:38px}.cols,.feat{grid-template-columns:1fr}.top nav a:not(.btn){display:none}}
"""

PAGES = [("overview.html", "Overview"), ("findings.html", "Findings"), ("scans.html", "Scan history"),
         ("agents.html", "Agent guard"), ("integrations.html", "Integrations")]
GITHUB = "https://github.com/Manavpatel06/Leak_Hunter"


def _head(title: str) -> str:
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" '
            f'content="width=device-width,initial-scale=1"><title>{title} · LeakHunter</title><style>{CSS}</style></head>')


def _app(active: str, title: str, sub: str, body: str, c: dict) -> str:
    nav = "".join(f'<a class="{"on" if f == active else ""}" href="{f}">{n}</a>' for f, n in PAGES)
    return (_head(title) + f"""<body><div class="app">
<aside><a class="logo" href="index.html"><span class="mark"><i></i></span>LeakHunter</a><div class="tag">Prove your data is safe.</div>
<nav>{nav}</nav><div class="side-foot"><a href="index.html">&larr; Product site</a><br>Open source · MIT</div></aside>
<div><header><div class="ws"><span class="live"></span>Snowflake <span class="muted">/ LEAKHUNTER</span></div>
<div class="muted">Last scan {c['when']} · <span class="pill green">Scan complete</span></div></header>
<main><div class="crumb">Workspace / {title}</div><h1>{title}</h1><p class="muted" style="margin:0 0 20px">{sub}</p>{body}</main></div></div></body></html>""")


def render_site(c: dict) -> dict[str, str]:
    prot = c["posture"] == "Protected"
    cards = f"""<div class="cards">
<div class="panel status {'' if prot else 'risk'}"><div class="shield">{'&#10003;' if prot else '!'}</div><div><div class="lab">Data posture</div><div class="big">{c['posture']}</div>
<div class="muted">{c['open_now']} open leaks · {c['found']} found and fixed · {c['crit']} critical</div></div></div>
<div class="panel"><div class="lab">Business continuity</div><div class="big">{c['lp']}<small> / {c['lt']}</small></div><div class="muted">analyst queries still pass after fixes</div></div>
<div class="panel"><div class="lab">Re-identification risk</div><div class="big">{c['reid']}<small> &rarr; 0</small></div><div class="muted">patients identifiable via public Census data</div></div></div>"""
    sevbar = "".join(f'<span class="sev {k.lower()}">{v} {k}</span>' for k, v in c["sev"].items() if v)
    pages = {}
    pages["overview.html"] = _app("overview.html", "Overview",
        "Where your warehouse stands right now, from the latest scan.", cards + f"""
<section class="grid2"><div class="panel"><h2>Findings</h2><div class="sevbar">{sevbar}</div>
<p class="muted" style="margin:0">{c['n_groups']} root causes found, every one fixed and re-verified.</p><a class="more" href="findings.html">View all findings &rarr;</a></div>
<div class="panel"><h2>Latest activity</h2><ul class="tl">{c['scans']}</ul><a class="more" href="scans.html">Scan history &rarr;</a></div></section>
<section class="grid2" style="grid-template-columns:1fr 1fr"><div class="panel"><div class="lab">Agent guard</div><div class="big">{c['b_block'] + c['fw_block']}<small> risky agent actions stopped</small></div>
<a class="more" href="agents.html">See what was blocked &rarr;</a></div>
<div class="panel"><div class="lab">Integrations</div><div class="big">1<small> connected · 3 planned</small></div><a class="more" href="integrations.html">Manage &rarr;</a></div></section>""", c)
    pages["findings.html"] = _app("findings.html", "Findings",
        "Every leak an attack proved, grouped by root cause. Click a row for the evidence trail and the exact fix.",
        f'<div class="sevbar">{sevbar}</div><div class="panel">{c["findings"]}</div>', c)
    pages["scans.html"] = _app("scans.html", "Scan history",
        f"Each scan runs {c['n_attacks']} attacks as a low-privilege analyst plus {c['lt']} legitimate queries.", f"""
<section class="grid2" style="margin-top:0"><div class="panel"><h2>Scans</h2><table><tr><th>Scan</th><th>Attacks</th><th>Leaks</th><th>Legit queries</th></tr>{c['round_rows']}</table></div>
<div class="panel"><h2>Timeline</h2><ul class="tl">{c['scans']}</ul></div></section>
<section><div class="panel"><h2>Legitimate workload (latest scan)</h2><p class="muted" style="margin:0 0 8px">The analyst queries your business depends on. A fix only counts if these still pass.</p>
<table><tr><th>ID</th><th>Query</th><th>Result</th></tr>{c['legit_rows']}</table></div></section>""", c)
    pages["agents.html"] = _app("agents.html", "Agent guard",
        "AI agents are getting write access to warehouses. LeakHunter checks what they install and what they change.", f"""
<div class="grid2" style="grid-template-columns:1fr 1fr">
<div class="panel"><div class="lab">Package check</div><div class="big">{c['b_block']}<small> blocked</small></div>
<p class="muted" style="margin:0 0 8px">Invented or look-alike packages an agent tried to install.</p><table><tr><th>Package</th><th>Verdict</th><th>Reason</th></tr>{c['b_rows']}</table></div>
<div class="panel"><div class="lab">Change firewall</div><div class="big">{c['fw_block']}<small> blocked · {c['fw_pass']} passed</small></div>
<p class="muted" style="margin:0 0 8px">Proposed changes are tested on a zero-copy clone before they reach production.</p><table><tr><th>Change</th><th>Verdict</th><th>Finding</th></tr>{c['fw_rows']}</table></div></div>""", c)
    pages["integrations.html"] = _app("integrations.html", "Integrations",
        "Connect a warehouse, choose who applies fixes, and schedule scans.", """<div class="ints">
<div class="panel int"><div><b>Snowflake</b><div class="muted">Key-pair service user, two roles</div></div><span class="pill green">Connected</span></div>
<div class="panel int"><div><b>Agent Skills</b><div class="muted">pii-guardian · bouncer (open standard)</div></div><span class="pill green">Active</span></div>
<div class="panel int"><div><b>Open-weight attacker</b><div class="muted">Gemma via Ollama, runs locally</div></div><span class="pill green">Active</span></div>
<div class="panel int"><div><b>Databricks · BigQuery · Postgres</b><div class="muted">Same attack, fix, verify loop</div></div><span class="pill">Planned</span></div></div>
<section><div class="panel"><h2>Connecting a warehouse</h2><ul class="tl">
<li><div class="dot blue"></div><div><b>Create two roles</b><div class="muted">A low-privilege role to attack as, and an admin role to apply and log fixes.</div></div></li>
<li><div class="dot blue"></div><div><b>Describe your workload</b><div class="muted">Add your attacks and must-keep-working queries as plain YAML.</div></div></li>
<li><div class="dot blue"></div><div><b>Schedule scans</b><div class="muted">After schema changes, new grants, or on a timer. Every step is kept as an audit trail.</div></div></li></ul></div></section>
<p class="muted" style="font-size:12px">All data in this workspace is synthetic. Attack sample rows are never stored in reports. Policy tags are pointers for a reviewer, not legal advice.</p>""", c)
    pages["index.html"] = _head("Prove your data is safe") + f"""<body><div class="lp">
<div class="top"><a class="brandrow" href="index.html"><span class="mark"><i></i></span>LeakHunter</a>
<nav><a href="#how">How it works</a><a href="#results">Results</a><a href="#agents">For AI agents</a><a href="{GITHUB}">GitHub</a><a class="btn primary" href="overview.html">Open dashboard</a></nav></div>
<div class="hero"><div><span class="eyebrow">Data leak assurance for Snowflake</span>
<h1>Prove your data is safe.</h1>
<p>LeakHunter attacks your warehouse the way a curious insider would, fixes every leak it can prove with Snowflake-native controls, and verifies that nothing your analysts rely on breaks.</p>
<div class="row"><a class="btn primary" href="overview.html">Open the dashboard</a><a class="btn" href="{GITHUB}">View on GitHub</a></div></div>
<div class="proof" id="results"><div class="k">Latest scan · synthetic hospital warehouse</div>
<div class="pr"><b>{c['found']} &rarr; {c['open_now']}</b><span>leaks proven by attacks, then left after fixes</span></div>
<div class="pr"><b>{c['lp']}/{c['lt']}</b><span>legitimate analyst queries still working</span></div>
<div class="pr"><b>{c['reid']} &rarr; 0</b><span>&ldquo;anonymous&rdquo; patients re-identified with free public Census data</span></div></div></div>
<div class="band" id="how"><h2>Audits find leaks once a year. Attackers look every day.</h2>
<p class="muted" style="max-width:640px;margin:0">Most leaks are not hacks: an unmasked column, a role granted &ldquo;for this week&rdquo;, a forgotten export, or data that is called anonymous but isn&rsquo;t. LeakHunter checks continuously and proves what is actually reachable.</p>
<div class="cols"><div><span class="num">01</span><h3>Attack</h3><p>A library of insider attacks plus new ones written by an open-weight model, all run as a low-privilege analyst.</p></div>
<div><span class="num">02</span><h3>Fix</h3><p>Each proven leak gets the smallest Snowflake-native fix: a masking policy, a revoked grant, or a dropped copy.</p></div>
<div><span class="num">03</span><h3>Prove</h3><p>Every attack runs again alongside your real analyst queries. Leaks must be zero and the work must still run.</p></div></div></div>
<div class="band" id="agents"><h2>Built for the age of AI agents.</h2><p class="muted" style="max-width:640px;margin:0">Agents now get write access to data platforms. LeakHunter guards the two ways they can open a new leak.</p>
<div class="feat"><div class="panel"><b>Package check</b><p class="muted" style="margin:6px 0 0">Blocks invented and look-alike packages before an agent installs them.</p></div>
<div class="panel"><b>Change firewall</b><p class="muted" style="margin:6px 0 0">Tests every proposed change on a zero-copy clone, attacks it, and only lets safe changes through.</p></div>
<div class="panel"><b>Open Agent Skills</b><p class="muted" style="margin:6px 0 0">The fix playbook is an open skill, so your own agent or a plain script can apply it.</p></div>
<div class="panel"><b>Audit trail</b><p class="muted" style="margin:6px 0 0">Every attack, fix and re-check is recorded, with each leak tagged to the rule it breaks.</p></div></div></div>
<div class="band"><div class="cta"><div><h2>See the latest scan.</h2><p>Findings, fixes and proof, straight from the warehouse.</p></div><a class="btn primary" href="overview.html">Open dashboard</a></div></div>
<div class="foot"><span>LeakHunter · open source (MIT) · built at sunhacks 2026</span><span>All demo data is synthetic.</span></div>
</div></body></html>"""
    return pages


def main() -> None:
    data = fetch()
    OUT_JSON.write_text(json.dumps(data, indent=1, default=str), encoding="utf-8")
    write_site(data)
    print(f"OK: wrote {OUT_DIR}/ ({len(data['scoreboard'])} rounds). Open site/index.html in a browser.")


def write_site(data: dict) -> None:
    OUT_DIR.mkdir(exist_ok=True)
    for name, page in build_html(data).items():
        (OUT_DIR / name).write_text(page, encoding="utf-8")
    OUT_HTML.write_text('<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0; url=../site/index.html">'
                        '<a href="../site/index.html">Open LeakHunter</a>', encoding="utf-8")


if __name__ == "__main__":
    main()
