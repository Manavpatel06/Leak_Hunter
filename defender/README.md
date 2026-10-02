# defender/ — owner: Manav

## Tasks
1. **Primary path (demo):** in Snowsight, open CoCo, give it `skills/pii-guardian/SKILL.md` + the playbook, and ask it to fix everything in `RESULTS.LEAK_LOG` and log each fix in `RESULTS.FIXES` with `APPLIED_BY = 'coco'`. Screenshot this for `docs/coco/`.
2. **Fallback path:** `apply_fixes.py` — reads `LEAK_LOG`, maps each leak to the playbook fix, applies it as `LH_ADMIN`, logs with `db.log_fix(..., applied_by='script')`. Use this if CoCo is unavailable or slow on stage.
3. Run `skills-ref validate ./skills/pii-guardian` before submission.

## Done when
After a defender run, `python -m referee.run_round` shows 0 leaks and legit 10/10.
