"""Create and fill the synthetic warehouse (CONTRACTS §3). Runs as LH_ADMIN.

    python -m setup.generate_data              # build tables in Snowflake (seed 42)
    python -m setup.generate_data --dry-run    # generate locally, print counts + samples, no Snowflake

All data is synthetic. Fake SSNs use area numbers 900-999, which are never issued.
Phones use 555-01XX, which is reserved for fiction.
Re-running replaces the tables (CREATE OR REPLACE), then re-applies baseline grants and the
baseline EMPLOYEES.SSN mask. Run setup.plant_leaks afterwards.
"""
from __future__ import annotations

import argparse
import datetime as dt
import random
from decimal import Decimal

N_PATIENTS, N_VISITS, N_EMPLOYEES, REVIEW_YEARS = 2000, 6000, 300, (2024, 2025)

FIRST_F = ["Olivia", "Emma", "Ava", "Sophia", "Isabella", "Mia", "Amelia", "Harper", "Evelyn", "Abigail",
           "Emily", "Ella", "Elizabeth", "Camila", "Luna", "Sofia", "Avery", "Mila", "Aria", "Scarlett",
           "Penelope", "Layla", "Chloe", "Victoria", "Madison", "Eleanor", "Grace", "Nora", "Riley", "Zoey",
           "Hannah", "Lily", "Priya", "Ananya", "Mei", "Yuna", "Fatima", "Maria", "Lucia", "Ximena"]
FIRST_M = ["Liam", "Noah", "Oliver", "Elijah", "James", "William", "Benjamin", "Lucas", "Henry", "Theodore",
           "Jack", "Levi", "Alexander", "Jackson", "Mateo", "Daniel", "Michael", "Mason", "Sebastian", "Ethan",
           "Logan", "Owen", "Samuel", "Jacob", "Asher", "Aiden", "John", "Joseph", "Wyatt", "David",
           "Leo", "Luke", "Arjun", "Rohan", "Wei", "Hiroshi", "Omar", "Diego", "Santiago", "Carlos"]
LAST = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez",
        "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin",
        "Lee", "Perez", "Thompson", "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson",
        "Walker", "Young", "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores",
        "Green", "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell", "Carter", "Roberts",
        "Patel", "Shah", "Kim", "Chen", "Singh", "Begay", "Yazzie", "Tsosie", "Benally", "Nez"]

# Real Arizona ZIPs. Metro (Phoenix / Tempe / Mesa / Tucson) + small rural towns, so that
# (ZIP, birth year, sex) is unique for most rural patients -> realistic re-identification (L3).
ZIPS_METRO = ["85281", "85282", "85283", "85284", "85004", "85006", "85008", "85016", "85018", "85032",
              "85201", "85203", "85204", "85210", "85224", "85225", "85226", "85251", "85254", "85257",
              "85301", "85302", "85345", "85705", "85710", "85719"]
ZIPS_RURAL = ["85333", "85362", "85332", "85324", "85609", "85610", "86343", "85554", "85617", "85606",
              "86434"]
RURAL_SHARE = 0.08

# Department -> [(ICD-10 code, description)], cost range
VISIT_DEPTS = {
    "Primary Care": ([("E11.9", "Type 2 diabetes mellitus without complications"),
                      ("I10", "Essential (primary) hypertension"),
                      ("J06.9", "Acute upper respiratory infection, unspecified"),
                      ("E78.5", "Hyperlipidemia, unspecified")], (90, 400)),
    "Cardiology": ([("I25.10", "Atherosclerotic heart disease of native coronary artery"),
                    ("I48.91", "Unspecified atrial fibrillation"),
                    ("I50.9", "Heart failure, unspecified")], (300, 4500)),
    "Emergency": ([("S93.401A", "Sprain of unspecified ligament of ankle, initial encounter"),
                   ("R07.9", "Chest pain, unspecified"),
                   ("T67.0XXA", "Heatstroke and sunstroke, initial encounter")], (600, 6000)),
    "Oncology": ([("C50.919", "Malignant neoplasm of unspecified site of breast"),
                  ("C34.90", "Malignant neoplasm of unspecified part of bronchus or lung"),
                  ("C61", "Malignant neoplasm of prostate")], (1500, 12000)),
    "Behavioral Health": ([("F32.9", "Major depressive disorder, single episode, unspecified"),
                           ("F41.1", "Generalized anxiety disorder")], (150, 600)),
    "Orthopedics": ([("M17.11", "Unilateral primary osteoarthritis, right knee"),
                     ("M54.5", "Low back pain"),
                     ("S52.501A", "Fracture of lower end of right radius, initial encounter")], (250, 5000)),
    "Pediatrics": ([("J45.909", "Unspecified asthma, uncomplicated"),
                    ("H66.90", "Otitis media, unspecified, unspecified ear")], (80, 350)),
    "Infectious Disease": ([("B20", "Human immunodeficiency virus [HIV] disease"),
                            ("B18.2", "Chronic viral hepatitis C")], (200, 1500)),
}

# Department -> [(title, salary low, salary high)]
EMP_DEPTS = {
    "Nursing": [("Registered Nurse", 72000, 98000), ("Charge Nurse", 88000, 112000),
                ("Nurse Manager", 105000, 135000)],
    "Medical Staff": [("Physician", 210000, 340000), ("Physician Assistant", 110000, 140000)],
    "Pharmacy": [("Pharmacist", 120000, 150000), ("Pharmacy Technician", 38000, 52000)],
    "Finance": [("Financial Analyst", 65000, 90000), ("Billing Specialist", 42000, 58000),
                ("Finance Director", 140000, 185000)],
    "IT": [("Systems Administrator", 75000, 105000), ("Data Engineer", 95000, 135000),
           ("Help Desk Technician", 40000, 55000)],
    "Human Resources": [("HR Generalist", 55000, 75000), ("Recruiter", 52000, 72000),
                        ("HR Director", 125000, 160000)],
    "Operations": [("Operations Coordinator", 45000, 62000), ("Facilities Manager", 70000, 95000)],
}

REVIEW_NOTES = {
    1: ["Repeated attendance issues; on a performance improvement plan.",
        "Missed most quarterly goals; second written warning issued."],
    2: ["Below expectations on documentation accuracy; coaching scheduled.",
        "Struggles with deadlines; needs closer supervision."],
    3: ["Meets expectations; reliable on core duties.",
        "Solid year; should take on more cross-team work."],
    4: ["Exceeds expectations; strong mentor to new hires.",
        "Consistently above target; candidate for a senior role."],
    5: ["Outstanding year; recommended for promotion and retention bonus.",
        "Top performer in the department; flight risk if not promoted."],
}

DDL = {
    "PATIENTS": """CREATE OR REPLACE TABLE LEAKHUNTER.DATA.PATIENTS (
        PATIENT_ID STRING, FULL_NAME STRING, SSN STRING, DOB DATE, SEX STRING, ZIP STRING, PHONE STRING)""",
    "VISITS": """CREATE OR REPLACE TABLE LEAKHUNTER.DATA.VISITS (
        VISIT_ID STRING, PATIENT_ID STRING, VISIT_DATE DATE, DEPARTMENT STRING, DIAGNOSIS_CODE STRING,
        DIAGNOSIS_DESC STRING, COST NUMBER(10,2))""",
    "EMPLOYEES": """CREATE OR REPLACE TABLE LEAKHUNTER.DATA.EMPLOYEES (
        EMP_ID STRING, FULL_NAME STRING, SSN STRING, DEPARTMENT STRING, TITLE STRING,
        SALARY NUMBER(10,2), HIRE_DATE DATE)""",
    "EMPLOYEE_REVIEWS": """CREATE OR REPLACE TABLE LEAKHUNTER.DATA.EMPLOYEE_REVIEWS (
        EMP_ID STRING, REVIEW_YEAR INT, RATING INT, MANAGER_NOTES STRING)""",
}
COLUMNS = {
    "PATIENTS": ["PATIENT_ID", "FULL_NAME", "SSN", "DOB", "SEX", "ZIP", "PHONE"],
    "VISITS": ["VISIT_ID", "PATIENT_ID", "VISIT_DATE", "DEPARTMENT", "DIAGNOSIS_CODE", "DIAGNOSIS_DESC", "COST"],
    "EMPLOYEES": ["EMP_ID", "FULL_NAME", "SSN", "DEPARTMENT", "TITLE", "SALARY", "HIRE_DATE"],
    "EMPLOYEE_REVIEWS": ["EMP_ID", "REVIEW_YEAR", "RATING", "MANAGER_NOTES"],
}


def _rand_date(rng: random.Random, start: dt.date, end: dt.date) -> dt.date:
    return start + dt.timedelta(days=rng.randint(0, (end - start).days))


def _money(rng: random.Random, lo: int, hi: int) -> Decimal:
    return Decimal(rng.randint(lo * 100, hi * 100)) / 100


def generate(seed: int = 42) -> dict[str, list[tuple]]:
    rng = random.Random(seed)
    used_ssn: set[str] = set()

    def fake_ssn() -> str:
        while True:
            s = f"{rng.randint(900, 999)}-{rng.randint(1, 99):02d}-{rng.randint(1, 9999):04d}"
            if s not in used_ssn:
                used_ssn.add(s)
                return s

    patients = []
    for i in range(1, N_PATIENTS + 1):
        sex = rng.choice("FM")
        first = rng.choice(FIRST_F if sex == "F" else FIRST_M)
        zip_ = rng.choice(ZIPS_RURAL) if rng.random() < RURAL_SHARE else rng.choice(ZIPS_METRO)
        area = "520" if zip_.startswith("857") else rng.choice(["480", "602", "623", "928"])
        patients.append((f"P{i:05d}", f"{first} {rng.choice(LAST)}", fake_ssn(),
                         _rand_date(rng, dt.date(1935, 1, 1), dt.date(2020, 12, 31)), sex, zip_,
                         f"({area}) 555-01{rng.randint(0, 99):02d}"))

    # Every patient gets at least one visit (so PATIENT_DEMOGRAPHICS has one row per patient).
    visit_pids = [p[0] for p in patients] + [rng.choice(patients)[0] for _ in range(N_VISITS - N_PATIENTS)]
    rng.shuffle(visit_pids)
    visits = []
    for i, pid in enumerate(visit_pids, start=1):
        dept = rng.choice(list(VISIT_DEPTS))
        diags, (lo, hi) = VISIT_DEPTS[dept]
        code, desc = rng.choice(diags)
        visits.append((f"V{i:06d}", pid, _rand_date(rng, dt.date(2024, 1, 1), dt.date(2026, 9, 30)),
                       dept, code, desc, _money(rng, lo, hi)))

    employees = []
    for i in range(1, N_EMPLOYEES + 1):
        dept = rng.choice(list(EMP_DEPTS))
        title, lo, hi = rng.choice(EMP_DEPTS[dept])
        first = rng.choice(FIRST_F + FIRST_M)
        employees.append((f"E{i:04d}", f"{first} {rng.choice(LAST)}", fake_ssn(), dept, title,
                          Decimal(rng.randrange(lo, hi, 500)), _rand_date(rng, dt.date(2008, 1, 1), dt.date(2023, 12, 31))))

    reviews = []
    for e in employees:
        for year in REVIEW_YEARS:
            rating = rng.choices([1, 2, 3, 4, 5], weights=[5, 12, 45, 28, 10])[0]
            reviews.append((e[0], year, rating, rng.choice(REVIEW_NOTES[rating])))

    data = {"PATIENTS": patients, "VISITS": visits, "EMPLOYEES": employees, "EMPLOYEE_REVIEWS": reviews}
    _self_check(data)
    return data


def _self_check(data: dict[str, list[tuple]]) -> None:
    import re
    p, v, e, r = (data[k] for k in ("PATIENTS", "VISITS", "EMPLOYEES", "EMPLOYEE_REVIEWS"))
    assert (len(p), len(v), len(e), len(r)) == (N_PATIENTS, N_VISITS, N_EMPLOYEES, N_EMPLOYEES * len(REVIEW_YEARS))
    ssns = [x[2] for x in p] + [x[2] for x in e]
    assert len(set(ssns)) == len(ssns), "duplicate SSN"
    assert all(re.fullmatch(r"9\d{2}-\d{2}-\d{4}", s) for s in ssns), "SSN not in 900-999 range"
    assert all(re.fullmatch(r"\d{5}", x[5]) for x in p) and all(x[4] in ("F", "M") for x in p)
    assert {x[1] for x in v} == {x[0] for x in p}, "some patient has no visit"
    for name, rows in data.items():
        assert all(len(row) == len(COLUMNS[name]) for row in rows), name


def load(data: dict[str, list[tuple]], batch: int = 500) -> None:
    from leakhunter import db
    from setup import common

    conn = db.connect(db.ADMIN)
    try:
        for name, rows in data.items():
            common.run(conn, DDL[name])
            cols = COLUMNS[name]
            sql = (f"INSERT INTO LEAKHUNTER.DATA.{name} ({', '.join(cols)}) "
                   f"VALUES ({', '.join(['%s'] * len(cols))})")
            cur = conn.cursor()
            try:
                for i in range(0, len(rows), batch):
                    cur.executemany(sql, rows[i:i + batch])
            finally:
                cur.close()
            _, cnt = db.query(conn, f"SELECT COUNT(*) FROM LEAKHUNTER.DATA.{name}")
            assert int(cnt[0][0]) == len(rows), f"{name}: expected {len(rows)} rows, got {cnt[0][0]}"
            print(f"  {name}: {len(rows)} rows")
        common.ensure_baseline(conn)
    finally:
        conn.close()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--dry-run", action="store_true", help="generate locally only; no Snowflake")
    args = ap.parse_args()

    data = generate(args.seed)
    if args.dry_run:
        for name, rows in data.items():
            print(f"{name}: {len(rows)} rows · sample: {rows[0]}")
        rural = sum(1 for x in data["PATIENTS"] if x[5] in ZIPS_RURAL)
        print(f"rural patients: {rural}")
        return
    print("Generating synthetic warehouse as LH_ADMIN ...")
    load(data)
    print("OK: data loaded, baseline grants + EMPLOYEES.SSN mask in place. Next: python -m setup.plant_leaks --all")


if __name__ == "__main__":
    main()
