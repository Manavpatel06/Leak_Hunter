# BOUNCER — LeakHunter's second skill. Owner: Reya

## One line
LeakHunter guards the data. Bouncer guards the door the AI walks through to reach it: before
any AI agent installs a Python package, Bouncer checks that it's real and trustworthy.

## Why it belongs in LeakHunter
A poisoned package on an analyst's laptop can read `.env` and steal the Snowflake key. Then
every masking policy LeakHunter applied is irrelevant, because the attacker *is* the admin.
Permissions are one unchecked leak path; packages AI agents install are the second.

Grounding (verify wording before putting numbers on a slide):
- USENIX Security 2025: 19.7% of LLM-recommended packages did not exist; 43% of invented names
  recurred on every rerun, which lets attackers register them first ("slopsquatting").
- Jan 2026: an invented npm package spread through 237 repos via AI-generated agent skills.
- Mar 2026: attackers compromised litellm, a package that handles AI API keys.

## What it checks today (minimal version, built)
| Check | Verdict |
|---|---|
| Package not on PyPI | BLOCK: likely invented by the AI |
| Name 1–2 letters from a popular package | WARN: possible typosquat |
| First published < 30 days ago | WARN |
| < 90 days old with a single release | WARN |
| Known vulnerabilities on latest version | WARN |
| No linked source repo | note only |

Code: `skills/bouncer/scripts/check.py` (standard library only, reads metadata, never installs).
Tested: `requests` → ALLOW, `reqeusts` → BLOCK (and flags the look-alike), invented name → BLOCK.

## Reya's tasks (in order)
1. **Wire logging (20 min).** Run `python skills/bouncer/scripts/check.py reqeusts --log` and confirm a row lands in `RESULTS.BOUNCER_LOG` (CONTRACTS §8). Needs `.env` set up and `sql/00_setup.sql` section E run.
2. **Scoreboard panel (20 min).** "Bouncer" panel on the scoreboard: latest checks with package, verdict (green/yellow/red), and reasons.
3. **Demo script (20 min).** `skills/bouncer/scripts/demo_gemma.py`: asks Gemma (via Ollama, `config.OLLAMA_MODEL`) "Which pip packages would you install to export a masked Snowflake report to PDF? Reply with package names only, one per line", then runs `check.py --log --by gemma` on every name. Live result is whatever Gemma says; keep a recorded backup.
4. **Agent wiring (10 min).** Point CoCo or Claude Code at `skills/bouncer/SKILL.md` and show it refusing a BLOCKed package. Screenshot into `docs/coco/`.
5. Validate: `skills-ref validate ./skills/bouncer`.

## Demo beat (30 s, after the re-check)
"Leaks don't only come from permissions. They come from the code your AI installs." Run the
Gemma demo → Bouncer verdicts appear on the scoreboard → any invented package is blocked.
If Gemma only suggests real packages, say so honestly and show `reqeusts` blocked instead.

## Roadmap (pitch only, not today)
Maintainer-history check using Snowflake's free GitHub Archive: repo age, maintainer count, and
newcomers recently given release rights, the pattern behind the xz-utils backdoor (CVSS 10.0).
That would also catch hijacked established packages, which today's version cannot.
