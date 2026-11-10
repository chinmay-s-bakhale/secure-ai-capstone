#!/usr/bin/env python3
"""
inject_scanner.py - Gate 4: custom prompt-injection / hardcoded-prompt scanner.

Walks every .py file in the repository and flags:
  * hardcoded system prompts   (SYSTEM_PROMPT = "...", system_message = "...", "role": "system")
  * common injection phrases   ("ignore previous instructions", "you are now", ...)

Exit code 1 if anything is found, 0 if the repo is clean.
Usage:  python inject_scanner.py [path]      (default path: current directory)
"""
import os
import re
import sys

# --- Hardcoded system-prompt patterns -------------------------------------
# Only flags assignments to a string LITERAL, so
#   SYSTEM_PROMPT = os.environ.get("SYSTEM_PROMPT")   -> clean
#   SYSTEM_PROMPT = "You are a helpful bot"            -> flagged
STRING_START = r"""\s*[rbfuRBFU]{0,2}(?:\"\"\"|'''|\"|')"""
SYSTEM_PROMPT_PATTERN = [
    re.compile(r"SYSTEM_PROMPT\s*=" + STRING_START),
    re.compile(r"system_message\s*=" + STRING_START),
    re.compile(r"""["']role["']\s*:\s*["']system["']"""),
]

# --- Injection phrases (case-insensitive) ---------------------------------
INJECTION_PHRASES = [
    "ignore previous instructions",
    "you are now",
    "pretend you are",
    "act as if you have no restrictions",
]

SKIP_DIRS = {".git", ".github", "venv", ".venv", "ai-lab", "redteam-env",
             "node_modules", "__pycache__", "site-packages"}
SELF = os.path.basename(__file__)


def scan_file(path):
    findings = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for lineno, line in enumerate(fh, start=1):
                for pat in SYSTEM_PROMPT_PATTERN:
                    if pat.search(line):
                        findings.append((lineno, "HARDCODED SYSTEM PROMPT", line.strip()))
                lowered = line.lower()
                for phrase in INJECTION_PHRASES:
                    if phrase in lowered:
                        findings.append((lineno, f"INJECTION PHRASE '{phrase}'", line.strip()))
    except OSError as exc:
        print(f"[warn] cannot read {path}: {exc}")
    return findings


def main(root="."):
    total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if not name.endswith(".py") or name == SELF:
                continue
            path = os.path.join(dirpath, name)
            for lineno, kind, text in scan_file(path):
                total += 1
                print(f"::error file={path},line={lineno}::{kind}")
                print(f"[FAIL] {path}:{lineno}  {kind}\n         > {text}")
    if total:
        print(f"\nPrompt-injection scanner: {total} issue(s) found. Pipeline blocked.")
        return 1
    print("Prompt-injection scanner: no hardcoded prompts or injection phrases found. Clean.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "."))
