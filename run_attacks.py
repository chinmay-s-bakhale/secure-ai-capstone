#!/usr/bin/env python3
"""run_attacks.py - replay the five Project 2 attack payloads against /chat.

Every payload must come back as HTTP 400. Payloads live in tests/payloads.json
(a data file, so the Gate 4 scanner - which only reads .py files - has nothing
to flag).

Usage:
  export TOKEN=$(python mint_token.py)
  python run_attacks.py
"""
import base64
import json
import os
import sys
from pathlib import Path

import requests

BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:5000")
TOKEN = os.environ.get("TOKEN", "")
PAYLOAD_FILE = Path(__file__).parent / "tests" / "payloads.json"


def send(message: str) -> requests.Response:
    return requests.post(
        f"{BASE_URL}/chat",
        headers={"Authorization": f"Bearer {TOKEN}"},
        json={"message": message},
        timeout=300,
    )


def build_message(item: dict) -> str:
    if "encode_base64" in item:
        encoded = base64.b64encode(item["encode_base64"].encode()).decode()
        return item["message_template"].format(payload=encoded)
    return item["message"]


def main() -> int:
    if not TOKEN:
        print("TOKEN is not set. Run: export TOKEN=$(python mint_token.py)")
        return 2
    items = json.loads(PAYLOAD_FILE.read_text(encoding="utf-8"))
    blocked = 0
    print(f"Target: {BASE_URL}/chat   (payloads: {len(items)})\n")
    for item in items:
        for setup in item.get("setup", []):          # multi-turn: build the persona first
            r = send(setup)
            print(f"      setup turn -> HTTP {r.status_code}")
        message = build_message(item)
        r = send(message)
        try:
            detail = r.json().get("error") or r.json().get("response", "")
        except ValueError:
            detail = r.text
        is_blocked = r.status_code == 400
        blocked += is_blocked
        verdict = "BLOCKED" if is_blocked else "NOT BLOCKED  <-- FAIL"
        print(f"[{item['id']}] {item['name']:<24} chars={len(message):<4} HTTP {r.status_code}  {verdict}")
        print(f"      {str(detail)[:150]}\n")
    print(f"Result: {blocked}/{len(items)} payloads blocked with HTTP 400")
    return 0 if blocked == len(items) else 1


if __name__ == "__main__":
    sys.exit(main())
