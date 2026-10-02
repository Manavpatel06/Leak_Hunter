# chatbot/ — owner: Manas · STRETCH (only after Checkpoint 2)

`bot.py`: `ask(question) -> (columns, rows)`. Turns a plain-English question into one SELECT using
`SNOWFLAKE.CORTEX.COMPLETE` (or AI_COMPLETE) with the analyst-visible schema, runs it as `LH_ANALYST`.
Attack files with `technique: chatbot` and a `prompt:` use it. Pitch point: because fixes live at the
data layer, the chatbot is protected automatically once masking is applied.
