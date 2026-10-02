# report/ — owner: Manav

`generate.py` writes `report/audit_report.md`: for each leak found, what leaked, which rule it breaks
(tags in `skills/pii-guardian/references/fix-playbook.md`), the fix applied, and the re-check result.
Ends with: rounds run, leaks before/after, legit queries before/after. Plain English, one page.

## Run
`python -m report.generate` (as LH_BOT via `.env`; read-only) → prints and writes `report/audit_report.md`.
Run it after the re-check round. Sample rows (EVIDENCE) are never copied into the report.
