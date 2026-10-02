"""Change Firewall: test a proposed change on a zero-copy clone, attack it, return PASS or BLOCK.

An AI agent (CoCo) writes SQL it wants to run on the warehouse. Instead of running it, it submits it here:

  0. Package Guard vets every package the change uses.
  1. Static check: only statement types the firewall can sandbox are allowed.
  2. Clone DATA, SCRATCH and GOVERNANCE into throwaway schemas (zero-copy), add a canary patient.
  3. Baseline: run the attack library on the clone BEFORE the change (so old leaks are not blamed on it).
  4. Apply the change to the clone only, and grant the target role (LH_ANALYST) read access to what it created.
  5. Attack as LH_ANALYST: library attacks again + probes on every new object (SSNs, names, canary, small groups).
  6. Verdict. BLOCK returns machine-readable feedback for the agent to rewrite and resubmit.
  7. PASS + --merge applies the change to production. Every attempt is saved to RESULTS.CHANGE_AUDIT.

Run (repo root):
  python -m firewall.leakcheck --sql-file firewall/examples/bad_patient_analytics.sql --json
  python -m firewall.leakcheck --sql-file firewall/examples/good_patient_analytics.sql --merge
Exit code: 0 PASS, 2 BLOCK, 3 firewall error.

Honest limits: a PASS means "not breakable by these attacks", not "provably safe". Account-wide changes
(role grants) cannot be tested on a clone and are always sent to a human. Enforcement in the demo comes
from the pii-guardian skill telling CoCo to submit here; real enforcement needs a Snowflake-side hook.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from leakhunter import db
from referee import run_attacks
from firewall import package_guard, probes

DB = "LEAKHUNTER"
SANDBOXED = ("DATA", "SCRATCH", "GOVERNANCE")  # schemas cloned into the sandbox
PROBE_ROWS = 5000
AUDIT_DDL = f"""CREATE TABLE IF NOT EXISTS {DB}.RESULTS.CHANGE_AUDIT (
  CHANGE_ID STRING, PARENT_ID STRING, SUBMITTED_BY STRING, CHANGE_SQL STRING, VERDICT STRING,
  MERGED BOOLEAN, ATTACKS_RUN INT, FINDINGS STRING, PACKAGES STRING,
  CREATED_AT TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP())"""

_ALLOWED = re.compile(
    r"^(CREATE\s+(OR\s+REPLACE\s+)?((SECURE|TEMP|TEMPORARY|TRANSIENT|RECURSIVE|MATERIALIZED|DYNAMIC|AGGREGATE)\s+)*"
    r"(VIEW|TABLE|FUNCTION|PROCEDURE|MASKING\s+POLICY|ROW\s+ACCESS\s+POLICY)\b|ALTER\s+(TABLE|VIEW)\b|GRANT\b|REVOKE\b)",
    re.I)
_CREATE_OBJ = re.compile(
    r"^CREATE\s+(?:OR\s+REPLACE\s+)?((?:(?:SECURE|TEMP|TEMPORARY|TRANSIENT|RECURSIVE|MATERIALIZED|DYNAMIC)\s+)*)"
    r"(VIEW|TABLE)\s+(?:IF\s+NOT\s+EXISTS\s+)?([\w.\"$]+)", re.I)
_ACCOUNT_SCOPE = re.compile(r"^(GRANT|REVOKE)\s+ROLE\b|\bON\s+(ACCOUNT|DATABASE|WAREHOUSE|INTEGRATION|USER|ROLE)\b", re.I)
_SCHEMA_REF = re.compile(rf'\b{DB}\s*\.\s*"?(\w+)"?', re.I)


# ---------------------------------------------------------------- parsing

def split_statements(sql: str) -> list[str]:
    """Split on ';' outside quotes, $$ bodies and comments."""
    out, buf, i, n, quote = [], [], 0, len(sql), None
    while i < n:
        c, two = sql[i], sql[i:i + 2]
        if quote == "$$":
            buf.append(c)
            if two == "$$":
                buf.append("$")
                i += 1
                quote = None
            i += 1
        elif quote:
            buf.append(c)
            if c == quote:
                if sql[i + 1:i + 2] == quote:
                    buf.append(quote)
                    i += 1
                else:
                    quote = None
            i += 1
        elif two == "--":
            while i < n and sql[i] != "\n":
                i += 1
        elif two == "/*":
            end = sql.find("*/", i + 2)
            i = n if end < 0 else end + 2
        elif two == "$$":
            quote = "$$"
            buf.append("$$")
            i += 2
        elif c in "'\"":
            quote = c
            buf.append(c)
            i += 1
        elif c == ";":
            stmt = "".join(buf).strip()
            if stmt:
                out.append(stmt)
            buf = []
            i += 1
        else:
            buf.append(c)
            i += 1
    tail = "".join(buf).strip()
    if tail:
        out.append(tail)
    return out


def qualify(name: str) -> tuple[str, str]:
    """(SCHEMA, OBJECT) for a created object; unqualified names land in DATA."""
    parts = [p.strip('"').upper() for p in name.split(".")]
    if len(parts) == 1:
        return "DATA", parts[0]
    return parts[-2], parts[-1]


def classify(stmt: str) -> dict:
    """Decide whether the firewall can sandbox this statement."""
    info = {"sql": stmt, "ok": True, "scope": "sandbox", "reason": "", "creates": None}
    if not _ALLOWED.match(stmt):
        return {**info, "ok": False, "kind": "unsupported_statement",
                "reason": f"statement type is not supported by the firewall (needs a human): {stmt[:60]!r}"}
    if _ACCOUNT_SCOPE.search(stmt):
        info["scope"] = "account"
        if stmt.upper().startswith("GRANT"):
            return {**info, "ok": False, "kind": "account_level",
                    "reason": "role/account grants are account-wide and cannot be tested on a clone; "
                              "a human must review them"}
        return info  # a REVOKE only removes access: skipped in the sandbox, passed through on merge
    for m in _SCHEMA_REF.finditer(stmt):
        if m.group(1).upper() not in SANDBOXED:
            return {**info, "ok": False, "kind": "outside_sandbox",
                    "reason": f"touches {DB}.{m.group(1).upper()}, which is outside the sandbox"}
    m = _CREATE_OBJ.match(stmt)
    if m:
        kind = "DYNAMIC TABLE" if "DYNAMIC" in m.group(1).upper() else m.group(2).upper()
        if "MATERIALIZED" in m.group(1).upper():
            kind = "VIEW"
        info["creates"] = (kind, *qualify(m.group(3)))
    return info


# ---------------------------------------------------------------- connections

class LazyConn:
    """A Snowflake connection opened on first use. prefetch() starts connecting in the background so the ~3 s
    login overlaps with other work, and a change that is blocked early never pays for a connection it did not use."""

    def __init__(self, role: str):
        self.role, self._conn, self._thread, self._err, self._used = role, None, None, None, False
        self._lock = threading.Lock()

    def _open(self) -> None:
        try:
            self._conn = db.connect(self.role)
        except Exception as e:
            self._err = e

    def prefetch(self) -> "LazyConn":
        with self._lock:
            if self._conn is None and self._thread is None:
                self._thread = threading.Thread(target=self._open, daemon=True)
                self._thread.start()
        return self

    def get(self):
        self._used = True
        self.prefetch()
        self._thread.join()
        if self._err:
            raise self._err
        return self._conn

    def close(self) -> None:
        if self._thread is not None and (self._used or not self._thread.is_alive()):
            self._thread.join()  # never wait on a login nobody needed (change blocked before cloning)
        if self._conn is not None:
            self._conn.close()


def _get(conn):
    return conn.get() if isinstance(conn, LazyConn) else conn


# ---------------------------------------------------------------- sandbox

def needed_schemas(stmts: list[dict]) -> list[str]:
    """DATA always (canary + default schema), plus any other sandboxed schema the change names."""
    names = {"DATA"}
    for s in stmts:
        names |= {m.group(1).upper() for m in _SCHEMA_REF.finditer(s["sql"]) if m.group(1).upper() in SANDBOXED}
    return sorted(names)


class Sandbox:
    """Throwaway zero-copy clones, inside LEAKHUNTER, of only the schemas the change touches.
    Attacks that read other schemas run against production unchanged, which is safe because the change cannot
    modify a schema it never references."""

    def __init__(self, admin, role: str, schemas: list[str] | None = None, tag: str | None = None):
        self.admin, self.role = admin, role
        self.tag = tag or uuid.uuid4().hex[:8].upper()
        self.names = {s: f"FW_{self.tag}_{s}" for s in (schemas or SANDBOXED)}
        self._ref = re.compile(rf'\b{DB}\s*\.\s*"?({"|".join(self.names)})"?\b', re.I)
        self.created = False

    def rewrite(self, sql: str) -> str:
        return self._ref.sub(lambda m: f"{DB}.{self.names[m.group(1).upper()]}", sql)

    def fqn(self, schema: str, obj: str) -> str:
        return f"{DB}.{self.names[schema]}.{obj}"

    def create(self) -> None:
        self.created = True
        for schema, clone in self.names.items():
            db.query(self.admin, f"CREATE SCHEMA {DB}.{clone} CLONE {DB}.{schema}")
            db.query(self.admin, f"GRANT USAGE ON SCHEMA {DB}.{clone} TO ROLE {self.role}")

    def add_canary(self) -> str:
        """A unique fake patient that exists only in the clone. Returns '' or a note if it could not be added."""
        c = probes.CANARY
        try:
            db.query(self.admin,
                     f"INSERT INTO {DB}.{self.names['DATA']}.PATIENTS "
                     f"(PATIENT_ID, FULL_NAME, SSN, DOB, SEX, ZIP, PHONE) "
                     f"SELECT '{c['PATIENT_ID']}', '{c['FULL_NAME']}', '{c['SSN']}', "
                     f"'{c['DOB']}'::DATE, '{c['SEX']}', '{c['ZIP']}', '{c['PHONE']}'")
            return ""
        except Exception as e:
            return f"canary not added: {str(e).splitlines()[0][:120]}"

    def drop(self) -> None:
        if not self.created:
            return
        for clone in self.names.values():
            try:
                db.query(self.admin, f"DROP SCHEMA IF EXISTS {DB}.{clone}")
            except Exception:
                pass


# ---------------------------------------------------------------- attacks

def attack_set() -> list[dict]:
    """Library + generated attacks that can run against a clone (sweep/chatbot need the whole DB)."""
    return [a for a in run_attacks.load_attacks() if a.get("technique") not in ("sweep", "chatbot")]


def run_library(analyst, sandbox: Sandbox | None, attacks: list[dict]) -> list[dict]:
    """Run the attacks as the analyst. sandbox=None runs them as written (production baseline)."""
    rows = []
    for a in attacks:
        sql = sandbox.rewrite(a.get("sql", "")) if sandbox else a.get("sql", "")
        r = run_attacks.run_attack(analyst, {**a, "sql": sql})
        rows.append({"id": a["id"], "goal": a.get("goal", ""), "technique": a.get("technique", ""),
                     "sql": r["sql"], "succeeded": r["succeeded"], "evidence": r["evidence"], "error": r["error"]})
    return rows


def probe_object(analyst, sandbox: Sandbox, schema: str, obj: str) -> tuple[list[dict], dict]:
    """Read the new object as the analyst and run every probe on it."""
    prod_name = f"{DB}.{schema}.{obj}"
    sql = f"SELECT * FROM {sandbox.fqn(schema, obj)} LIMIT {PROBE_ROWS}"
    try:
        cols, rows = db.query(analyst, sql)
    except Exception as e:
        step = {"object": prod_name, "sql": sql, "rows": 0, "error": str(e).splitlines()[0][:200], "findings": []}
        return [], step
    findings = probes.analyze_object(prod_name, cols, rows)
    step = {"object": prod_name, "sql": sql, "rows": len(rows), "columns": cols, "error": "",
            "findings": [f["kind"] for f in findings]}
    return findings, step


# ---------------------------------------------------------------- the gate

def _log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _log_bouncer(admin, pk: dict, submitted_by: str, notes: list[str]) -> None:
    """Every package Bouncer looked at goes to RESULTS.BOUNCER_LOG, so it shows on the scoreboard."""
    by = submitted_by if submitted_by in ("coco", "gemma", "claude", "human") else "human"
    for r in pk.get("checked", []):
        b = r.get("bouncer")
        if not b:
            continue
        try:
            db.log_bouncer(admin, package=r["name"], verdict=b["verdict"], reasons="; ".join(b["reasons"]),
                           requested_by=by)
        except Exception as e:
            notes.append(f"bouncer log not saved: {str(e).splitlines()[0][:100]}")
            return


def check_change(sql: str, admin, analyst, *, role: str = db.ANALYST, merge: bool = False, keep: bool = False,
                 submitted_by: str = "coco", parent_id: str = "", bouncer: bool = True, log=_log) -> dict:
    """Run the whole firewall on one proposed change. Never raises: errors become verdict ERROR.
    `admin` / `analyst` may be live connections or LazyConn objects."""
    result = {"change_id": uuid.uuid4().hex[:12], "parent_id": parent_id, "verdict": "BLOCK", "merged": False,
              "findings": [], "packages": {}, "statements": 0, "attacks_run": 0, "preexisting_leaks": [],
              "attack_path": [], "feedback": {}, "notes": [], "timings": {}}
    sandbox: Sandbox | None = None
    stmts: list[dict] = []
    t0 = last = time.time()

    def lap(name: str) -> None:
        nonlocal last
        now = time.time()
        result["timings"][name] = round(now - last, 1)
        last = now

    try:
        # 0-1. Package Guard (policy + Bouncer's live PyPI check) and the static check: no clone yet
        log("[0/6] Package Guard + Bouncer")
        if isinstance(admin, LazyConn):
            admin.prefetch()  # the login overlaps with the PyPI lookups
        pk = package_guard.check_sql(sql, use_bouncer=bouncer)
        result["packages"] = pk
        for p in pk["problems"]:
            result["findings"].append({"kind": "package_" + p["status"], "blocking": True, "object": p["name"],
                                       "detail": p["detail"], "evidence": "",
                                       "fix": "Remove it or use an approved package (firewall/packages.yaml)."})
        lap("packages")
        log("[1/6] Static check")
        stmts.extend(classify(s) for s in split_statements(sql))
        result["statements"] = len(stmts)
        if not stmts:
            result["findings"].append({"kind": "empty_change", "blocking": True, "object": "", "detail":
                                       "no SQL statements found", "evidence": "", "fix": "Submit the SQL to run."})
        for s in stmts:
            if not s["ok"]:
                result["findings"].append({"kind": s["kind"], "blocking": True, "object": s["sql"][:80],
                                           "detail": s["reason"], "evidence": "",
                                           "fix": "Split this out and ask a human to apply it."})
        lap("static")
        if result["findings"]:  # fail fast: nothing cloned, the attacker connection is never opened
            result["notes"].append("blocked before cloning")
            return result

        if isinstance(analyst, LazyConn):
            analyst.prefetch()
        adm = _get(admin)
        sandbox = Sandbox(adm, role, needed_schemas(stmts))

        # 2-3. Baseline on production runs concurrently while the clone is built
        attacks = attack_set()
        log(f"[2/6] Cloning {', '.join(sandbox.names)} (zero-copy) while running {len(attacks)} baseline attacks")
        ana = _get(analyst)
        with ThreadPoolExecutor(max_workers=1) as pool:
            baseline = pool.submit(run_library, ana, None, attacks)
            sandbox.create()
            note = sandbox.add_canary()
            before = {r["id"]: r for r in baseline.result()}
        if note:
            result["notes"].append(note)
        lap("clone+baseline")

        # 4. Apply the change to the clone
        log("[4/6] Applying the change to the clone")
        db.query(adm, f"USE SCHEMA {DB}.{sandbox.names['DATA']}")
        created = []
        for s in stmts:
            if s["scope"] == "account":
                result["notes"].append(f"skipped in sandbox (account-wide, pass-through on merge): {s['sql'][:60]}")
                continue
            try:
                db.query(adm, sandbox.rewrite(s["sql"]))
            except Exception as e:
                result["findings"].append({
                    "kind": "change_failed", "blocking": True, "object": s["sql"][:80],
                    "detail": f"the statement failed on the clone: {str(e).splitlines()[0][:200]}",
                    "evidence": "", "fix": "Fix the SQL so it runs, then resubmit."})
                return result
            if s["creates"]:
                created.append(s["creates"])
        for kind, schema, obj in created:
            if schema in sandbox.names:
                try:
                    db.query(adm, f"GRANT SELECT ON {kind} {sandbox.fqn(schema, obj)} TO ROLE {role}")
                except Exception as e:
                    result["notes"].append(f"could not grant {role} on {obj}: {str(e).splitlines()[0][:100]}")
        lap("apply")

        # 5. Attack the clone as the analyst
        log(f"[5/6] Attacking as {role}")
        after = run_library(ana, sandbox, attacks)
        result["attacks_run"] = len(after)
        for r in after:
            result["attack_path"].append({"step": "library_attack", "attack_id": r["id"], "goal": r["goal"],
                                          "sql": r["sql"], "succeeded": r["succeeded"],
                                          "evidence": r["evidence"], "error": r["error"]})
            if r["succeeded"] and not before[r["id"]]["succeeded"]:
                result["findings"].append({
                    "kind": "new_leak", "blocking": True, "object": r["id"],
                    "detail": f"attack {r['id']} ('{r['goal']}') failed before the change and succeeds after it",
                    "evidence": r["evidence"],
                    "fix": "Undo whatever re-opened this path (usually a missing mask or an extra grant)."})
            elif r["succeeded"]:
                result["preexisting_leaks"].append(r["id"])
        for kind, schema, obj in created:
            if schema in sandbox.names:
                found, step = probe_object(ana, sandbox, schema, obj)
                result["attack_path"].append({"step": "object_probe", **step})
                result["findings"] += found
                result["attacks_run"] += probes.PROBE_COUNT
        lap("attack")
        return result
    except Exception as e:  # the firewall must never fail open
        result["verdict"] = "ERROR"
        result["notes"].append(f"firewall error: {e}")
        result["findings"].append({"kind": "firewall_error", "blocking": True, "object": "", "detail": str(e)[:300],
                                   "evidence": "", "fix": "Ask a human; the change was NOT applied."})
        return result
    finally:
        try:
            adm = _get(admin)
        except Exception as e:
            result["notes"].append(f"no admin connection, change NOT recorded: {e}")
        else:
            if sandbox and not keep:
                sandbox.drop()
            _log_bouncer(adm, result["packages"], submitted_by, result["notes"])
            _finish(result, sql, stmts, adm, merge, submitted_by, log)
        result["timings"]["total"] = round(time.time() - t0, 1)


def _finish(result: dict, sql: str, stmts: list[dict], admin, merge: bool, submitted_by: str, log) -> None:
    """Set the verdict, build feedback, merge on PASS, write the audit record."""
    if result["verdict"] != "ERROR":
        result["verdict"] = "BLOCK" if any(f["blocking"] for f in result["findings"]) else "PASS"
    result["feedback"] = {
        "verdict": result["verdict"], "resubmit": result["verdict"] == "BLOCK",
        "reasons": [{"kind": f["kind"], "object": f["object"], "why": f["detail"], "fix": f["fix"]}
                    for f in result["findings"] if f["blocking"]]}
    log(f"[6/6] Verdict: {result['verdict']}")
    if result["verdict"] == "PASS" and merge:
        try:
            db.query(admin, f"USE SCHEMA {DB}.DATA")
            for s in stmts:
                db.query(admin, s["sql"])
            result["merged"] = True
            log("      merged to production")
        except Exception as e:
            result["notes"].append(f"merge failed after PASS: {str(e).splitlines()[0][:200]}")
            result["feedback"]["merge_error"] = result["notes"][-1]
    insert = (f"INSERT INTO {DB}.RESULTS.CHANGE_AUDIT (CHANGE_ID, PARENT_ID, SUBMITTED_BY, CHANGE_SQL, VERDICT, "
              f"MERGED, ATTACKS_RUN, FINDINGS, PACKAGES) VALUES (%(id)s, %(parent)s, %(by)s, %(sql)s, %(v)s, "
              f"%(m)s, %(n)s, %(f)s, %(p)s)")
    row = {"id": result["change_id"], "parent": result["parent_id"], "by": submitted_by, "sql": sql,
           "v": result["verdict"], "m": result["merged"], "n": result["attacks_run"],
           "f": json.dumps({"findings": result["findings"], "attack_path": result["attack_path"],
                            "preexisting_leaks": result["preexisting_leaks"]}),
           "p": ", ".join(c["name"] for c in result["packages"].get("checked", []))}
    try:
        try:
            db.query(admin, insert, row)
        except Exception:  # first use: the table does not exist yet
            db.query(admin, AUDIT_DDL)
            db.query(admin, insert, row)
    except Exception as e:
        result["notes"].append(f"audit record not saved: {str(e).splitlines()[0][:120]}")


# ---------------------------------------------------------------- CLI

def render(result: dict) -> str:
    """Human-readable verdict, shaped like a rejected pull request."""
    lines = [f"CHANGE {result['change_id']}: {result['verdict']}"
             + ("  (merged to production)" if result["merged"] else "")]
    for f in result["findings"]:
        lines += [f"  x {f['kind']}: {f['detail']}"]
        if f["evidence"]:
            lines.append(f"      evidence: {f['evidence']}")
        lines.append(f"      fix: {f['fix']}")
    for p in result["packages"].get("checked", []):
        if p.get("bouncer"):
            lines.append(f"  bouncer: {p['name']} -> {p['bouncer']['verdict']} ({p['bouncer']['reasons'][0]})")
    if result["verdict"] == "PASS":
        lines.append(f"  ok: {result['attacks_run']} attacks and probes found nothing new")
    if result["preexisting_leaks"]:
        lines.append(f"  note: leaks already present before this change (not blamed on it): "
                     f"{', '.join(result['preexisting_leaks'])}")
    lines += [f"  note: {n}" for n in result["notes"]]
    if result.get("timings"):
        lines.append("  time: " + ", ".join(f"{k} {v}s" for k, v in result["timings"].items()))
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--sql-file", help="file containing the proposed SQL change")
    src.add_argument("--sql", help="the proposed SQL change as a string")
    ap.add_argument("--merge", action="store_true", help="on PASS, apply the change to production")
    ap.add_argument("--json", action="store_true", help="print the full verdict as JSON (for CoCo)")
    ap.add_argument("--no-bouncer", action="store_true", help="skip Bouncer's live PyPI lookups (offline)")
    ap.add_argument("--keep", action="store_true", help="keep the clone schemas for inspection")
    ap.add_argument("--submitted-by", default="coco")
    ap.add_argument("--parent-id", default="", help="CHANGE_ID of the BLOCKed attempt this one rewrites")
    args = ap.parse_args()
    sql = Path(args.sql_file).read_text(encoding="utf-8") if args.sql_file else args.sql

    admin, analyst = LazyConn(db.ADMIN).prefetch(), LazyConn(db.ANALYST).prefetch()  # both logins start now
    try:
        result = check_change(sql, admin, analyst, merge=args.merge, keep=args.keep,
                              submitted_by=args.submitted_by, parent_id=args.parent_id, bouncer=not args.no_bouncer)
    finally:
        admin.close()
        analyst.close()
    print(json.dumps(result, indent=2, default=str) if args.json else render(result))
    sys.exit({"PASS": 0, "BLOCK": 2}.get(result["verdict"], 3))


if __name__ == "__main__":
    main()
