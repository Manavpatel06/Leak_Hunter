#!/usr/bin/env python3
"""One entry point for the LeakHunter demo. Run from the repo root:

  python demo/run_demo.py doctor        preflight: env, key, both roles, tables, Ollama, PyPI (30 s)
  python demo/run_demo.py agent         the AI-agent story: Bouncer vets packages, the firewall BLOCKs a leaky
                                        view, the rewrite PASSes   [--merge applies the PASS, --cleanup removes it]
  python demo/run_demo.py round         one referee round (attacks + legit queries) -> scoreboard row
  python demo/run_demo.py scoreboard    open the Streamlit scoreboard
  python demo/run_demo.py showcase      rebuild the interactive dashboard from live data and open it
  python demo/run_demo.py all           doctor, round, agent (no merge)
  python demo/run_demo.py loop          full proof, end to end: reset, plant all leaks, round (leaks), defender
                                        fixes, round (re-check: 0 leaks, legit all pass), audit report, dashboard
  python demo/run_demo.py judge         judge break: someone exports PATIENTS to SCRATCH -> round (caught),
                                        defender, round (closed), report + dashboard refreshed
  python demo/run_demo.py dashboard     rebuild report/dashboard.html + report/audit_report.md from RESULTS

Everything it prints is real output from the real tools; nothing is canned except `--sample` (no Ollama).
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

OK, WARN, FAIL = "ok  ", "WARN", "FAIL"


def say(status: str, msg: str) -> str:
    print(f"  [{status}] {msg}")
    return status


def banner(text: str) -> None:
    print(f"\n=== {text} " + "=" * max(3, 66 - len(text)))


def doctor() -> int:
    """Everything the demo needs, checked in one go. FAIL blocks the demo; WARN has a fallback."""
    banner("doctor")
    results = []

    from leakhunter import config
    missing = [k for k in ("SNOWFLAKE_ACCOUNT", "SNOWFLAKE_USER") if not os.getenv(k)]
    results.append(say(FAIL if missing else OK, f".env: missing {', '.join(missing)}" if missing else ".env loaded"))
    key = os.getenv("SNOWFLAKE_PRIVATE_KEY_FILE")
    if key:
        results.append(say(OK if Path(key).exists() else FAIL, f"private key file {'found' if Path(key).exists() else 'NOT FOUND: ' + key}"))

    def pypi() -> tuple[str, str]:
        try:
            from firewall import package_guard
            r = package_guard.bouncer_check(["requests", "reqeusts"])
            ok = r["requests"]["verdict"] == "ALLOW" and r["reqeusts"]["verdict"] == "BLOCK"
            return (OK if ok else WARN), "Bouncer reaches PyPI: requests ALLOW, reqeusts BLOCK"
        except Exception as e:
            return WARN, f"Bouncer could not check PyPI ({str(e)[:60]}); it will fail closed"

    def ollama() -> tuple[str, str]:
        try:
            import ollama
            names = [m.model for m in ollama.Client(host=config.OLLAMA_HOST).list().models]
            have = any(config.OLLAMA_MODEL.split(":")[0] in n for n in names)
            return (OK if have else WARN), (f"Ollama up, model {config.OLLAMA_MODEL} " + ("ready" if have else "NOT pulled"))
        except Exception:
            return WARN, "Ollama not running: Gemma attacks/demo need it (use `agent --sample` meanwhile)"

    with ThreadPoolExecutor(max_workers=4) as pool:
        f_pypi, f_ollama = pool.submit(pypi), pool.submit(ollama)
        if not missing:
            from leakhunter import db
            from firewall.leakcheck import LazyConn
            admin, analyst = LazyConn(db.ADMIN).prefetch(), LazyConn(db.ANALYST).prefetch()
            try:
                a = admin.get()
                results.append(say(OK, "connected as LH_ADMIN"))
                cur = analyst.get()
                _, row = db.query(cur, "SELECT CURRENT_ROLE(), CURRENT_SECONDARY_ROLES()")
                results.append(say(OK, f"connected as {row[0][0]} (secondary roles off)"))
                _, t = db.query(a, "SELECT TABLE_SCHEMA || '.' || TABLE_NAME, ROW_COUNT FROM "
                                   "LEAKHUNTER.INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA IN ('DATA','RESULTS','SCRATCH')")
                have = {n: c for n, c in t}
                for need in ("DATA.PATIENTS", "DATA.VISITS", "DATA.EMPLOYEES", "RESULTS.ATTACK_RUNS",
                             "RESULTS.LEGIT_RUNS", "RESULTS.FIXES", "RESULTS.BOUNCER_LOG"):
                    if need not in have:
                        results.append(say(FAIL, f"table {need} is missing (run sql/00_setup.sql, setup/generate_data.py)"))
                results.append(say(OK, f"warehouse: {have.get('DATA.PATIENTS', 0)} patients, "
                                       f"{have.get('DATA.VISITS', 0)} visits, {have.get('DATA.EMPLOYEES', 0)} employees"))
                planted = db.query(a, "SELECT COUNT(*) FROM LEAKHUNTER.RESULTS.PLANTED")[1][0][0]
                results.append(say(OK if planted else WARN, f"{planted} leaks planted" if planted else
                                   "no leaks planted yet: python -m setup.plant_leaks --all"))
                if not config.PUBLIC_ZIP_TABLE:
                    results.append(say(WARN, "LH_PUBLIC_ZIP_TABLE empty: attack A03 (re-identification) cannot run yet"))
            except Exception as e:
                results.append(say(FAIL, f"Snowflake: {str(e).splitlines()[0][:100]}"))
            finally:
                admin.close()
                analyst.close()
        for fut in (f_pypi, f_ollama):
            results.append(say(*fut.result()))

    fails, warns = results.count(FAIL), results.count(WARN)
    print(f"\n  {'READY' if not fails else 'NOT READY'}: {fails} failed, {warns} warnings")
    return 1 if fails else 0


def run(cmd: list[str], title: str) -> int:
    banner(title)
    print("  $ " + " ".join(cmd))
    return subprocess.call([sys.executable, "-u", *cmd], env={**os.environ, "PYTHONIOENCODING": "utf-8"})


def agent(args) -> int:
    """The agent story. Each step is the real tool; the SQL files are in firewall/examples/."""
    banner("1. an AI agent wants to install packages: Bouncer checks them at the door")
    bouncer = ["skills/bouncer/scripts/demo_gemma.py", "--extra", "reqeusts"]
    if args.sample:
        bouncer.append("--sample")
    code = run(bouncer, "Bouncer")
    if code == 3:
        print("  (Ollama is not running, falling back to the sample list)")
        run([*bouncer, "--sample"], "Bouncer (sample)")

    banner("2. the agent proposes: 'build an analytics view of patients by ZIP and birth date'")
    print((ROOT / "firewall/examples/bad_patient_analytics.sql").read_text(encoding="utf-8"))
    run(["-m", "firewall.leakcheck", "--sql-file", "firewall/examples/bad_patient_analytics.sql"],
        "Change Firewall: clone it, attack the clone")

    banner("3. the agent reads the BLOCK, generalizes ZIP and birth date, resubmits")
    print((ROOT / "firewall/examples/good_patient_analytics.sql").read_text(encoding="utf-8"))
    cmd = ["-m", "firewall.leakcheck", "--sql-file", "firewall/examples/good_patient_analytics.sql"]
    if args.merge:
        cmd.append("--merge")
    run(cmd, "Change Firewall: second attempt" + (" (merging on PASS)" if args.merge else " (dry run)"))

    if args.merge and args.cleanup:
        from leakhunter import db
        c = db.connect(db.ADMIN)
        db.query(c, "DROP VIEW IF EXISTS LEAKHUNTER.DATA.PATIENT_ANALYTICS")
        c.close()
        print("  cleaned up: dropped the demo view LEAKHUNTER.DATA.PATIENT_ANALYTICS")
    print("\n  Scoreboard panels 'Bouncer' and 'Change Firewall' now show these runs: "
          "python demo/run_demo.py scoreboard")
    return 0


def loop() -> int:
    """The whole story in one go. Stops at the first failing step."""
    steps = [(["-m", "setup.reset"], "reset (rehearsal state)"),
             (["-m", "setup.plant_leaks", "--all"], "plant leaks L1-L6"),
             (["-m", "referee.run_round"], "ROUND 1: attack (expect leaks, legit all pass)"),
             (["-m", "defender.apply_fixes"], "DEFEND: pii-guardian playbook fixes, logged to RESULTS.FIXES"),
             (["-m", "referee.run_round"], "ROUND 2: re-check (expect 0 leaks, legit all pass)"),
             (["-m", "report.generate"], "audit report -> report/audit_report.md"),
             (["-m", "report.dashboard"], "dashboard -> report/dashboard.html"),
             (["demo/build_showcase.py"], "interactive showcase -> docs/showcase.html")]
    for cmd, title in steps:
        if run(cmd, title):
            print(f"\n  STOPPED at: {title}")
            return 1
    print("\n  Done. Open docs/showcase.html (interactive) or report/dashboard.html (one page), or: python demo/run_demo.py scoreboard")
    return 0


def judge() -> int:
    """demo/judge_breaks.sql option 1, run as LH_ADMIN, then caught -> fixed -> proven."""
    from leakhunter import db
    banner("judge break: 'quick export for an analysis' (demo/judge_breaks.sql option 1)")
    c = db.connect(db.ADMIN)
    try:
        for sql in ("CREATE OR REPLACE TABLE LEAKHUNTER.SCRATCH.JUDGE_EXPORT AS SELECT * FROM LEAKHUNTER.DATA.PATIENTS",
                    "GRANT USAGE ON SCHEMA LEAKHUNTER.SCRATCH TO ROLE LH_ANALYST",
                    "GRANT SELECT ON TABLE LEAKHUNTER.SCRATCH.JUDGE_EXPORT TO ROLE LH_ANALYST"):
            print("  SQL> " + sql)
            db.query(c, sql)
    finally:
        c.close()
    for cmd, title in ((["-m", "referee.run_round"], "ROUND: the SSN sweep (A07) catches the export"),
                       (["-m", "defender.apply_fixes"], "DEFEND"),
                       (["-m", "referee.run_round"], "ROUND: re-check"),
                       (["-m", "report.generate"], "audit report"),
                       (["-m", "report.dashboard"], "dashboard"),
                       (["demo/build_showcase.py"], "interactive showcase")):
        if run(cmd, title):
            return 1
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["doctor", "agent", "round", "scoreboard", "showcase", "all", "loop", "judge", "dashboard"])
    ap.add_argument("--merge", action="store_true", help="agent: apply the PASSed change to production")
    ap.add_argument("--cleanup", action="store_true", help="agent: with --merge, drop the demo view afterwards")
    ap.add_argument("--sample", action="store_true", help="agent: canned package list instead of live Gemma")
    args = ap.parse_args()
    sys.stdout.reconfigure(line_buffering=True)

    start = time.time()
    if args.command == "doctor":
        return doctor()
    if args.command == "round":
        return run(["-m", "referee.run_round"], "referee round")
    if args.command == "scoreboard":
        return run(["-m", "streamlit", "run", "scoreboard/app.py"], "scoreboard (Ctrl+C to stop)")
    if args.command == "showcase":
        import webbrowser
        code = run(["demo/build_showcase.py"], "build dashboard")
        webbrowser.open((ROOT / "docs" / "showcase.html").as_uri())
        return code
    if args.command == "agent":
        return agent(args)
    if args.command == "loop":
        return loop()
    if args.command == "judge":
        return judge()
    if args.command == "dashboard":
        return run(["-m", "report.generate"], "audit report") or run(["-m", "report.dashboard"], "dashboard")
    if doctor():  # all
        return 1
    run(["-m", "referee.run_round"], "referee round")
    agent(args)
    print(f"\nDone in {round(time.time() - start)}s.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
