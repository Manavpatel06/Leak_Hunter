"""Snowflake helpers shared by setup/ and defender/ (owner: Manav).

Every statement goes through leakhunter.db (shared connection + query helpers).
All helpers are idempotent: they check the current state first and only change
what is needed, so plant / reset / fix can be re-run safely any number of times.
"""
from __future__ import annotations

import re

from leakhunter import db

# ---- Contract names (docs/CONTRACTS.md §1, §3, §5) -------------------------------------------
DB = "LEAKHUNTER"
PATIENTS = "LEAKHUNTER.DATA.PATIENTS"
VISITS = "LEAKHUNTER.DATA.VISITS"
EMPLOYEES = "LEAKHUNTER.DATA.EMPLOYEES"
REVIEWS = "LEAKHUNTER.DATA.EMPLOYEE_REVIEWS"
DEMOGRAPHICS_VIEW = "LEAKHUNTER.DATA.PATIENT_DEMOGRAPHICS"   # L3
VISIT_DETAILS_VIEW = "LEAKHUNTER.DATA.VISIT_DETAILS"         # L6
SCRATCH = "LEAKHUNTER.SCRATCH"
EXPORT_OLD = "LEAKHUNTER.SCRATCH.PATIENTS_EXPORT_OLD"        # L5
RESULTS_TABLES = ("ATTACK_RUNS", "LEGIT_RUNS", "FIXES", "PLANTED")

MASK_SSN = "LEAKHUNTER.GOVERNANCE.MASK_SSN"
MASK_NAME = "LEAKHUNTER.GOVERNANCE.MASK_NAME"
MASK_ZIP = "LEAKHUNTER.GOVERNANCE.MASK_ZIP"
MASK_DOB = "LEAKHUNTER.GOVERNANCE.MASK_DOB"

ANALYST = db.ANALYST
HR = "LH_HR"

# Baseline protection that is NOT a planted leak: employee SSNs are always masked.
# Without it, the A07 SSN sweep finds EMPLOYEES.SSN and leaks can never reach 0.
BASELINE_MASKS = [(EMPLOYEES, "SSN", MASK_SSN)]

# Baseline (legitimate) access, CONTRACTS §2
BASELINE_GRANTS = [
    f"GRANT SELECT ON TABLE {PATIENTS} TO ROLE {ANALYST}",
    f"GRANT SELECT ON TABLE {VISITS} TO ROLE {ANALYST}",
    f"GRANT SELECT ON TABLE {EMPLOYEES} TO ROLE {ANALYST}",
    f"GRANT SELECT ON TABLE {REVIEWS} TO ROLE {HR}",
]

_IDENT = re.compile(r"^[A-Z_][A-Z0-9_$]*$")


def safe_ident(name: str) -> str:
    """Validate a Snowflake identifier we did not write ourselves (e.g. a judge's table name).
    Raises instead of ever splicing an unexpected string into SQL."""
    n = str(name).strip().strip('"').upper()
    if not _IDENT.match(n):
        raise ValueError(f"refusing unexpected identifier: {name!r}")
    return n


def run(conn, sql: str, dry_run: bool = False) -> str:
    print(("  [dry-run] " if dry_run else "  SQL> ") + " ".join(sql.split()))
    if not dry_run:
        db.query(conn, sql)
    return sql


def run_all(conn, statements: list[str], dry_run: bool = False) -> list[str]:
    return [run(conn, s, dry_run) for s in statements]


# ---- State checks -----------------------------------------------------------------------------
def object_exists(conn, fq_name: str, kind: str = "TABLE") -> bool:
    """kind: TABLE or VIEW. fq_name: DB.SCHEMA.NAME"""
    dbn, schema, name = fq_name.split(".")
    _, rows = db.query(conn, f"SHOW {kind}S LIKE '{safe_ident(name)}' IN SCHEMA {dbn}.{safe_ident(schema)}")
    return len(rows) > 0


def column_policy(conn, table: str, column: str) -> str | None:
    """Fully qualified masking policy on table.column, or None."""
    cols, rows = db.query(
        conn,
        "SELECT POLICY_DB, POLICY_SCHEMA, POLICY_NAME, POLICY_KIND, REF_COLUMN_NAME "
        "FROM TABLE(LEAKHUNTER.INFORMATION_SCHEMA.POLICY_REFERENCES("
        f"REF_ENTITY_NAME => '{table}', REF_ENTITY_DOMAIN => 'table'))",
    )
    for r in rows:
        rec = dict(zip(cols, r))
        if rec["POLICY_KIND"] == "MASKING_POLICY" and str(rec["REF_COLUMN_NAME"]).upper() == column.upper():
            return f'{rec["POLICY_DB"]}.{rec["POLICY_SCHEMA"]}.{rec["POLICY_NAME"]}'.upper()
    return None


def analyst_grants(conn) -> list[dict]:
    """Direct grants held by LH_ANALYST (SHOW GRANTS TO ROLE)."""
    cols, rows = db.query(conn, f"SHOW GRANTS TO ROLE {ANALYST}")
    out = []
    for r in rows:
        rec = {c.lower(): v for c, v in zip(cols, r)}
        rec["name"] = str(rec.get("name", "")).replace('"', "").upper()
        rec["granted_on"] = str(rec.get("granted_on", "")).upper()
        rec["privilege"] = str(rec.get("privilege", "")).upper()
        out.append(rec)
    return out


def analyst_has_hr(conn) -> bool:
    return any(g["granted_on"] == "ROLE" and g["name"] == HR for g in analyst_grants(conn))


def analyst_has_scratch(conn) -> bool:
    return any(g["granted_on"] == "SCHEMA" and g["name"] == SCRATCH and g["privilege"] == "USAGE"
               for g in analyst_grants(conn))


def scratch_objects(conn) -> list[tuple[str, str]]:
    """[(kind, fq_name)] for every table and view in SCRATCH."""
    out = []
    for kind in ("TABLE", "VIEW"):
        cols, rows = db.query(conn, f"SHOW {kind}S IN SCHEMA {SCRATCH}")
        idx = [c.lower() for c in cols].index("name")
        for r in rows:
            out.append((kind, f"{SCRATCH}.{safe_ident(r[idx])}"))
    return out


# ---- Idempotent changes (each returns the SQL actually executed; [] = already in place) ----------
def set_mask(conn, table: str, column: str, policy: str, dry_run: bool = False) -> list[str]:
    current = column_policy(conn, table, column)
    if current == policy.upper():
        return []
    stmts = []
    if current:
        stmts.append(f"ALTER TABLE {table} MODIFY COLUMN {column} UNSET MASKING POLICY")
    stmts.append(f"ALTER TABLE {table} MODIFY COLUMN {column} SET MASKING POLICY {policy}")
    return run_all(conn, stmts, dry_run)


def unset_mask(conn, table: str, column: str, dry_run: bool = False) -> list[str]:
    if column_policy(conn, table, column) is None:
        return []
    return [run(conn, f"ALTER TABLE {table} MODIFY COLUMN {column} UNSET MASKING POLICY", dry_run)]


def revoke_hr(conn, dry_run: bool = False) -> list[str]:
    if not analyst_has_hr(conn):
        return []
    return [run(conn, f"REVOKE ROLE {HR} FROM ROLE {ANALYST}", dry_run)]


def revoke_scratch(conn, dry_run: bool = False) -> list[str]:
    if not analyst_has_scratch(conn):
        return []
    return [run(conn, f"REVOKE USAGE ON SCHEMA {SCRATCH} FROM ROLE {ANALYST}", dry_run)]


def drop_scratch_object(conn, fq_name: str, kind: str = "TABLE", dry_run: bool = False) -> list[str]:
    """Hard rule (pii-guardian): never drop anything outside LEAKHUNTER.SCRATCH."""
    parts = fq_name.upper().split(".")
    if len(parts) != 3 or ".".join(parts[:2]) != SCRATCH:
        raise ValueError(f"refusing to drop outside {SCRATCH}: {fq_name}")
    name = f"{SCRATCH}.{safe_ident(parts[2])}"
    if not object_exists(conn, name, kind):
        return []
    return [run(conn, f"DROP {kind} IF EXISTS {name}", dry_run)]


def ensure_baseline(conn, dry_run: bool = False) -> None:
    run_all(conn, BASELINE_GRANTS, dry_run)
    for table, column, policy in BASELINE_MASKS:
        set_mask(conn, table, column, policy, dry_run)
