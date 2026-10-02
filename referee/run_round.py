"""One full referee round: every attack + every legit query, tagged with the next round number.

Contract: docs/CONTRACTS.md §8 (round rules).
Run:  python -m referee.run_round
"""
from __future__ import annotations

from leakhunter import db
from referee import run_attacks, run_legit


def main() -> None:
    admin, analyst = db.connect(db.ADMIN), db.connect(db.ANALYST)
    try:
        round_no = db.next_round(admin)
        print(f"Round {round_no}: attacks (as {db.ANALYST})")
        attacks = run_attacks.run_all(admin, analyst, round_no)
        print(f"Round {round_no}: legit queries (as {db.ANALYST})")
        legit = run_legit.run_all(admin, analyst, round_no)

        leaks = sum(r["succeeded"] for r in attacks)
        passed = sum(r["passed"] for r in legit)
        print(f"\nRound {round_no}: leaks {leaks}/{len(attacks)}, legit {passed}/{len(legit)}")

        _, rows = db.query(admin, "SELECT LEAKS, ATTACKS, LEGIT_PASSED, LEGIT_TOTAL "
                                  "FROM LEAKHUNTER.RESULTS.SCOREBOARD WHERE ROUND_NO = %(r)s",
                           {"r": round_no})
        if rows:
            print("SCOREBOARD row: leaks {}/{}, legit {}/{}".format(*rows[0]))
    finally:
        admin.close()
        analyst.close()


if __name__ == "__main__":
    main()
