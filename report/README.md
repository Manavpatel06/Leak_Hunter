# report/ — owner: Reya

`generate.py` writes `report/audit_report.md`: for each leak found, what leaked, which rule it breaks
(tags in `skills/pii-guardian/references/fix-playbook.md`), the fix applied, and the re-check result.
Ends with: rounds run, leaks before/after, legit queries before/after. Plain English, one page.
