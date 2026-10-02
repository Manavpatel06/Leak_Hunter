# attacker/ — owner: Manas

## Tasks
1. `gemma_attacker.py` — for each goal in `attacks/goals.yaml`, give Gemma (via Ollama, model from `config.OLLAMA_MODEL`) the schema the analyst can see (`LEAKHUNTER.INFORMATION_SCHEMA.COLUMNS` queried as `LH_ANALYST`) plus 3 library attacks as examples. Save each valid result as `attacks/generated/G###.yaml` in the CONTRACTS §6 format with `source: gemma`.
2. Reject anything that is not read-only (`db.is_read_only`). Retry once on SQL errors, feeding the error back.

## Done when
`python -m attacker.gemma_attacker` writes at least 3 valid generated attacks and at least 1 succeeds before fixes.
