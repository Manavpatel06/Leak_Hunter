#!/usr/bin/env python3
"""Bouncer demo: ask Gemma which packages it would install, then check every one at the door.

Run from the repo root:
    python skills/bouncer/scripts/demo_gemma.py            # live Gemma via Ollama (config.OLLAMA_MODEL)
    python skills/bouncer/scripts/demo_gemma.py --sample   # no Ollama: canned list, logged as 'human'

Every verdict is written to RESULTS.BOUNCER_LOG (shows on the scoreboard) unless --no-log.
Live results are whatever Gemma says. If Gemma only suggests real packages, that is the honest result;
use --extra reqeusts to also show a look-alike being blocked.
"""
from __future__ import annotations

import argparse
import importlib.util
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT))

QUESTION = ("Which pip packages would you install to export a masked Snowflake report to PDF? "
            "Reply with package names only, one per line.")
# Used only with --sample. Includes one invented-looking name, like an AI hallucination would produce.
SAMPLE = ["snowflake-connector-python", "reportlab", "pandas", "snowflake-pdf-exporter", "reqeusts"]


def load_check():
    spec = importlib.util.spec_from_file_location("bouncer_check", HERE / "check.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def ask_gemma() -> list[str]:
    import ollama
    from leakhunter import config
    client = ollama.Client(host=config.OLLAMA_HOST)
    reply = client.chat(model=config.OLLAMA_MODEL, messages=[{"role": "user", "content": QUESTION}])
    names = []
    for line in reply["message"]["content"].splitlines():
        name = re.sub(r"^[\s\-*\d.)]+", "", line).strip().strip("`").split()[0:1]
        if name and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name[0]):
            names.append(name[0])
    return list(dict.fromkeys(names))[:10]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sample", action="store_true", help="skip Ollama and use a canned list (logged as 'human')")
    ap.add_argument("--no-log", action="store_true", help="do not write to RESULTS.BOUNCER_LOG")
    ap.add_argument("--extra", nargs="*", default=[], help="more package names to check, e.g. reqeusts")
    args = ap.parse_args()

    asked_by = "gemma"
    if args.sample:
        names, asked_by = SAMPLE, "human"
        print("SAMPLE list (not live Gemma):", ", ".join(names))
    else:
        try:
            names = ask_gemma()
        except Exception as e:
            print(f"Could not reach Gemma ({str(e).splitlines()[0][:100]}). Is Ollama running? "
                  f"Use --sample for the canned list.", file=sys.stderr)
            return 3
        print("Gemma suggested:", ", ".join(names) or "(nothing parseable)")
    names += [n for n in args.extra if n not in names]

    check = load_check()
    blocked = 0
    for pkg in names:
        result = check.check(pkg)
        mark = {"ALLOW": "ok   ", "WARN": "WARN ", "BLOCK": "BLOCK"}[result["verdict"]]
        print(f"  [{mark}] {pkg}: {result['reasons'][0]}")
        blocked += result["verdict"] == "BLOCK"
        if not args.no_log:
            try:
                check.log_result(result, asked_by)
            except Exception as e:
                print(f"    (not logged: {str(e).splitlines()[0][:100]})", file=sys.stderr)
    print(f"\n{blocked} of {len(names)} blocked at the door.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
