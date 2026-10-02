"""Offline self-test for the Change Firewall: python -m firewall.selftest

Runs the real gate (leakcheck.check_change) against a fake warehouse, so no Snowflake account is needed.
It proves the logic: statement parsing, sandbox rewriting, the probes, Package Guard, the BLOCK ->
rewrite -> PASS loop, merge only on PASS, and that production is never touched before a PASS.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from leakhunter import db
from firewall import leakcheck, package_guard, probes
from firewall.leakcheck import classify, split_statements

EX = Path(__file__).with_name("examples")
failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"  {detail}" if detail and not ok else ""))
    if not ok:
        failures.append(name)


class FakeWarehouse:
    """Answers db.query() like Snowflake would for the statements the firewall sends."""

    def __init__(self, view_rows):
        self.view_rows = view_rows  # (cols, rows) readable from the new view
        self.log: list[str] = []

    def query(self, conn, sql, params=None):
        self.log.append(sql.strip())
        s = sql.strip()
        m = re.match(r"SELECT \* FROM (\S+) LIMIT", s)
        if m and m.group(1).upper().endswith(".PATIENT_ANALYTICS"):
            return self.view_rows
        if s.upper().startswith("SELECT"):  # library attacks: masked / nothing readable
            return ["FULL_NAME", "SSN"], [("REDACTED", "***-**-1234")]
        return [], []

    def on_prod(self) -> list[str]:  # statements that ran outside any FW_ clone
        return [q for q in self.log if re.search(r"LEAKHUNTER\.(DATA|SCRATCH|GOVERNANCE)\b", q, re.I)
                and "CLONE" not in q and not q.upper().startswith("USE SCHEMA LEAKHUNTER.FW_")
                and "RESULTS" not in q]


def run_gate(sql: str, view_rows, merge=False, bouncer=False):
    fake = FakeWarehouse(view_rows)
    real = db.query
    db.query = fake.query
    try:
        res = leakcheck.check_change(sql, object(), object(), merge=merge, bouncer=bouncer, log=lambda m: None)
    finally:
        db.query = real
    return res, fake


def row_level(n=40):
    cols = ["ZIP", "DOB", "SEX", "DIAGNOSIS_DESC"]
    rows = [(f"85{i:03d}", f"19{50 + i % 40}-0{1 + i % 9}-1{i % 9}", "F" if i % 2 else "M", "Flu") for i in range(n)]
    rows.append(("85999", "1931-03-07", "F", "Flu"))  # the canary
    return cols, rows


def aggregated():
    return ["ZIP3", "BIRTH_DECADE", "SEX", "DIAGNOSIS_DESC", "PATIENTS"], \
        [("852", 1970, "F", "Flu", 12), ("852", 1970, "M", "Flu", 9), ("859", 1930, "F", "Flu", 7)]


def main() -> None:
    print("parsing")
    stmts = split_statements("-- hi\nSELECT 1; CREATE FUNCTION F() AS $$ a; b $$; /* c; */ SELECT 'x;y'")
    check("splits on ; outside quotes/$$/comments", len(stmts) == 3, str(stmts))
    check("allows CREATE VIEW", classify("CREATE OR REPLACE SECURE VIEW LEAKHUNTER.DATA.V AS SELECT 1")["ok"])
    check("records created object", classify("CREATE VIEW V AS SELECT 1")["creates"] == ("VIEW", "DATA", "V"))
    check("blocks DROP", not classify("DROP TABLE LEAKHUNTER.DATA.PATIENTS")["ok"])
    check("blocks INSERT", not classify("INSERT INTO LEAKHUNTER.DATA.PATIENTS VALUES (1)")["ok"])
    check("blocks GRANT ROLE (account-wide)", classify("GRANT ROLE LH_HR TO ROLE LH_ANALYST")["kind"] == "account_level")
    check("REVOKE ROLE passes through", classify("REVOKE ROLE LH_HR FROM ROLE LH_ANALYST")["ok"])
    check("blocks RESULTS schema", classify("CREATE VIEW LEAKHUNTER.RESULTS.V AS SELECT 1")["kind"] == "outside_sandbox")

    print("sandbox rewrite")
    sb = leakcheck.Sandbox(object(), "LH_ANALYST", tag="ABC")
    out = sb.rewrite("SELECT * FROM LEAKHUNTER.DATA.PATIENTS JOIN leakhunter.scratch.X ON 1=1")
    check("DATA and SCRATCH point at the clone", "LEAKHUNTER.FW_ABC_DATA.PATIENTS" in out and "FW_ABC_SCRATCH.X" in out, out)
    check("RESULTS is not rewritten", sb.rewrite("SELECT 1 FROM LEAKHUNTER.RESULTS.T") == "SELECT 1 FROM LEAKHUNTER.RESULTS.T")

    print("probes")
    cols, rows = row_level()
    kinds = {f["kind"] for f in probes.analyze_object("V", cols, rows)}
    check("row-level ZIP+DOB+SEX view -> small_group + canary", kinds == {"small_group", "canary_exposed"}, str(kinds))
    check("aggregated view with HAVING >= 5 is clean", probes.analyze_object("V", *aggregated()) == [])
    c2, r2 = aggregated()
    r2.append(("852", 1980, "F", "Flu", 2))
    check("aggregated view with a group of 2 is flagged",
          [f["kind"] for f in probes.analyze_object("V", c2, r2)] == ["small_group"])
    check("SSN detected, masked SSN is not",
          probes.find_ssn("V", ["SSN"], [("123-45-6789",)]) and not probes.find_ssn("V", ["SSN"], [("***-**-6789",)]))
    check("names detected, REDACTED is not",
          probes.find_names("V", ["FULL_NAME"], [("Ann",)]) and not probes.find_names("V", ["FULL_NAME"], [("REDACTED",)]))
    check("DEPARTMENT_NAME is not a person name", not probes.find_names("V", ["DEPARTMENT_NAME"], [("ER",)]))

    print("package guard")
    pg = package_guard.check_sql((EX / "bad_package.sql").read_text(encoding="utf-8"), use_bouncer=False)
    names = {p["name"]: p["status"] for p in pg["problems"]}
    check("typosquat 'pandsa' caught", names.get("pandsa") == "typosquat", str(names))
    check("socket import denied", names.get("socket") == "denied", str(names))
    check("egress integration flagged", any(s == "egress" for s in names.values()), str(names))
    check("numpy approved", "numpy" not in names)
    check("clean SQL passes", package_guard.check_sql("CREATE VIEW V AS SELECT 1", use_bouncer=False)["verdict"] == "PASS")
    check("requirements check", package_guard.check_requirements("pandas==2.0\nrequestz\n", use_bouncer=False)["verdict"] == "BLOCK")

    print("gate: bad view")
    bad, fake = run_gate((EX / "bad_patient_analytics.sql").read_text(encoding="utf-8"), row_level(), merge=True)
    check("BLOCK", bad["verdict"] == "BLOCK", bad["verdict"])
    check("not merged", not bad["merged"])
    check("feedback is machine-readable", bad["feedback"]["resubmit"] and bad["feedback"]["reasons"]
          and all({"kind", "why", "fix"} <= set(r) for r in bad["feedback"]["reasons"]))
    check("attack path recorded", any(s.get("step") == "object_probe" for s in bad["attack_path"]))
    check("production untouched", not any(re.match(r"(CREATE|GRANT|ALTER)", q, re.I) and "FW_" not in q
                                          and "CHANGE_AUDIT" not in q for q in fake.log), str(fake.on_prod()))
    check("only the schema the change needs is cloned and dropped",
          sum("CREATE SCHEMA" in q for q in fake.log) == 1 and sum("DROP SCHEMA" in q for q in fake.log) == 1,
          str([q for q in fake.log if "SCHEMA" in q]))
    check("audit row written", any("INSERT INTO LEAKHUNTER.RESULTS.CHANGE_AUDIT" in q for q in fake.log))

    print("gate: rewritten view")
    good, fake = run_gate((EX / "good_patient_analytics.sql").read_text(encoding="utf-8"), aggregated(), merge=True)
    check("PASS", good["verdict"] == "PASS", json.dumps(good["findings"])[:200])
    check("merged to production", good["merged"])
    check("merge ran the original SQL on prod",
          any(q.startswith("CREATE OR REPLACE VIEW LEAKHUNTER.DATA.PATIENT_ANALYTICS") for q in fake.log))
    ok_nomerge, fake = run_gate((EX / "good_patient_analytics.sql").read_text(encoding="utf-8"), aggregated())
    check("PASS without --merge does not touch prod", ok_nomerge["verdict"] == "PASS" and not ok_nomerge["merged"]
          and not any(q.startswith("CREATE OR REPLACE VIEW LEAKHUNTER.DATA.") for q in fake.log))

    print("gate: package + account-level changes stop before cloning")
    pkg, fake = run_gate((EX / "bad_package.sql").read_text(encoding="utf-8"), aggregated())
    check("bad package -> BLOCK, nothing cloned", pkg["verdict"] == "BLOCK" and not any("CLONE" in q for q in fake.log))
    role, fake = run_gate("GRANT ROLE LH_HR TO ROLE LH_ANALYST", aggregated())
    check("role grant -> BLOCK, nothing cloned", role["verdict"] == "BLOCK" and not any("CLONE" in q for q in fake.log))

    print("bouncer integration")
    package_guard._bouncer_cache["pandsa"] = {"verdict": "BLOCK", "reasons": ["does not exist on PyPI: likely invented"]}
    package_guard._bouncer_cache["pandas"] = {"verdict": "ALLOW", "reasons": ["established package"]}
    bsql = "CREATE FUNCTION F() RETURNS INT LANGUAGE PYTHON RUNTIME_VERSION='3.11' PACKAGES=('pandsa','pandas') HANDLER='f' AS $$def f(): return 1$$"
    pk = package_guard.check_sql(bsql)
    st = {r["name"]: r["status"] for r in pk["checked"]}
    check("typosquat of approved + not on PyPI -> invented", st.get("pandsa") == "invented", str(st))
    check("approved package skips Bouncer (no network)", "bouncer" not in next(r for r in pk["checked"] if r["name"] == "pandas"))
    bad, fake = run_gate(bsql, aggregated(), bouncer=True)
    check("firewall blocks on Bouncer verdict before cloning", bad["verdict"] == "BLOCK" and not any("CLONE" in q for q in fake.log))
    check("Bouncer verdict logged to BOUNCER_LOG", any("BOUNCER_LOG" in q for q in fake.log))
    check("render shows Bouncer evidence", "bouncer: pandsa -> BLOCK" in leakcheck.render(bad))

    print("gate: failure modes")

    def boom(conn, sql, params=None):
        if sql.startswith("CREATE SCHEMA"):
            raise RuntimeError("no privilege")
        return [], []
    real, db.query = db.query, boom
    try:
        err = leakcheck.check_change("CREATE VIEW V AS SELECT 1", object(), object(), bouncer=False, log=lambda m: None)
    finally:
        db.query = real
    check("clone failure fails closed (never PASS)", err["verdict"] == "ERROR" and not err["merged"], err["verdict"])

    print(f"\n{'ALL PASSED' if not failures else f'{len(failures)} FAILED: ' + ', '.join(failures)}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
