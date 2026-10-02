# legit/ — owner: Manas

Write 10 queries in `queries.yaml` that a real hospital/HR analyst needs every day (format: CONTRACTS §7).
They must pass **before and after** fixes: aggregates only, group by `LEFT(ZIP,3)` / `YEAR(DOB)` / `DEPARTMENT`,
never select names or SSNs. Three examples are already in `queries.yaml`.
