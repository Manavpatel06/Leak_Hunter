"""Attack probes for ONE new object (view/table) that a proposed change created.

Pure functions: they take the columns and rows the analyst role could read and return findings.
No Snowflake calls here, so they are easy to test (python -m firewall.selftest).

Probes:
  ssn_exposed     any cell that looks like an SSN (a masked '***-**-1234' does not match)
  name_exposed    a person-name column holding real names instead of 'REDACTED'
  canary_exposed  the planted canary record (unique name / SSN / ZIP+birth date) is readable
  small_group     quasi-identifiers (ZIP, birth date, sex, age) describe groups smaller than K_MIN
"""
from __future__ import annotations

import re
from collections import Counter

PROBE_COUNT = 4  # ssn, names, canary, small group
K_MIN = 5  # fewer people than this sharing the same quasi-identifiers = re-identifiable

# Canary record: inserted into the CLONE only (never production) before the change is applied.
CANARY = {"PATIENT_ID": "CANARY-0001", "FULL_NAME": "CANARY ZED", "SSN": "999-99-9999",
          "DOB": "1931-03-07", "SEX": "F", "ZIP": "85999", "PHONE": "555-0100"}

_SSN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
_NAME_COL = re.compile(r"^(FULL_|FIRST_|LAST_|PATIENT_|EMPLOYEE_|CUSTOMER_)?NAME$")
_QUASI = [re.compile(r"ZIP|POSTAL"), re.compile(r"DOB|BIRTH"), re.compile(r"^SEX$|GENDER"), re.compile(r"^AGE")]
_COUNT_COL = re.compile(r"^(N|CNT|COUNT|TOTAL|SIZE|HEADCOUNT|PATIENTS|CUSTOMERS|RECORDS|PEOPLE)$|_COUNT$|^NUM_|^COUNT_")

FIX = {
    "ssn_exposed": "Do not select SSN. Drop the column, or apply LEAKHUNTER.GOVERNANCE.MASK_SSN to it.",
    "name_exposed": "Do not expose names. Drop FULL_NAME, or mask it with LEAKHUNTER.GOVERNANCE.MASK_NAME.",
    "canary_exposed": "A planted canary record is readable through this object. Remove direct identifiers and "
                      "generalize quasi-identifiers (ZIP to LEFT(ZIP,3), DOB to YEAR(DOB) or a decade).",
    "small_group": f"Rows describe fewer than {K_MIN} people. Generalize ZIP to LEFT(ZIP,3), DOB to YEAR(DOB) "
                   f"or a decade, drop SEX or age detail if needed, and add HAVING COUNT(*) >= {K_MIN}.",
}


def _finding(kind: str, obj: str, detail: str, evidence: str) -> dict:
    return {"kind": kind, "blocking": True, "object": obj, "detail": detail,
            "evidence": evidence[:300], "fix": FIX[kind]}


def _quasi_columns(cols: list[str]) -> list[int]:
    return [i for i, c in enumerate(cols) if any(p.search(c.upper()) for p in _QUASI)]


def _is_number(v) -> bool:
    try:
        float(v)
        return v is not None
    except (TypeError, ValueError):
        return False


def _count_column(cols: list[str], rows: list[tuple]) -> int | None:
    for i, c in enumerate(cols):
        if _COUNT_COL.search(c.upper()) and rows and all(_is_number(r[i]) for r in rows):
            return i
    return None


def find_ssn(obj: str, cols, rows) -> dict | None:
    for r in rows:
        for c, v in zip(cols, r):
            if v is not None and _SSN.search(str(v)):
                return _finding("ssn_exposed", obj, f"column {c} contains full SSNs", f"{c}: {v}")
    return None


def find_names(obj: str, cols, rows) -> dict | None:
    for i, c in enumerate(cols):
        if _NAME_COL.match(c.upper()):
            real = [r[i] for r in rows if r[i] not in (None, "", "REDACTED")]
            if real:
                return _finding("name_exposed", obj, f"column {c} returns real names ({len(real)} rows)",
                                f"{c}: {real[0]}")
    return None


def find_canary(obj: str, cols, rows) -> dict | None:
    for r in rows:
        cells = [str(v) for v in r if v is not None]
        if any(CANARY["FULL_NAME"] in c or CANARY["SSN"] in c or CANARY["PATIENT_ID"] in c for c in cells):
            return _finding("canary_exposed", obj, "the canary patient's name, SSN or ID is readable",
                            ", ".join(f"{c}={v}" for c, v in zip(cols, r)))
        zip_hit = any(c == CANARY["ZIP"] for c in cells)
        dob_hit = any(c.startswith(CANARY["DOB"]) for c in cells) or \
            (zip_hit and any(c in ("1931", "1931.0") for c in cells))
        if zip_hit and dob_hit:
            return _finding("canary_exposed", obj, "the canary patient is isolated by full ZIP + birth date",
                            ", ".join(f"{c}={v}" for c, v in zip(cols, r)))
    return None


def find_small_group(obj: str, cols, rows) -> dict | None:
    q = _quasi_columns(cols)
    if len(q) < 2 or not rows:
        return None
    qnames = [cols[i] for i in q]
    count_col = _count_column(cols, rows)
    if count_col is not None:  # aggregated object: each row is already a group with its own size
        small = [(r, int(float(r[count_col]))) for r in rows if int(float(r[count_col])) < K_MIN]
        if not small:
            return None
        k = min(n for _, n in small)
        ev = "; ".join(f"{[r[i] for i in q]} -> {n}" for r, n in small[:3])
        return _finding("small_group", obj, f"{len(small)} groups on {qnames} have fewer than {K_MIN} people "
                                             f"(smallest: {k})", ev)
    groups = Counter(tuple(r[i] for i in q) for r in rows)  # row-level object: one row ~ one person
    small = [(g, n) for g, n in groups.items() if n < K_MIN]
    if not small:
        return None
    k = min(n for _, n in small)
    share = sum(n for _, n in small)
    ev = "; ".join(f"{list(g)} -> {n}" for g, n in sorted(small, key=lambda x: x[1])[:3])
    return _finding("small_group", obj, f"{share} of {len(rows)} rows are in groups smaller than {K_MIN} "
                                        f"on {qnames} (smallest: {k}), so people are re-identifiable", ev)


def analyze_object(obj: str, cols: list[str], rows: list[tuple]) -> list[dict]:
    """Run every probe on what the analyst can read from `obj`. Empty list = nothing found."""
    probes = (find_ssn, find_names, find_canary, find_small_group)
    return [f for f in (p(obj, cols, rows) for p in probes) if f]
