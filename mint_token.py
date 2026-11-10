#!/usr/bin/env python3
"""mint_token.py - print a signed JWT for testing the /chat endpoint.

Usage:
  python mint_token.py                 # valid for 60 minutes, user 'alice'
  python mint_token.py --user bob --minutes 10
  python mint_token.py --expired       # already-expired token (expect 401)

Requires JWT_SECRET in the environment (the same value the server uses).
"""
import argparse
import sys

from auth import create_token


def main() -> int:
    parser = argparse.ArgumentParser(description="Issue a test JWT")
    parser.add_argument("--user", default="alice", help="value of the 'sub' claim")
    parser.add_argument("--minutes", type=int, default=60, help="token lifetime in minutes")
    parser.add_argument("--expired", action="store_true", help="issue an already-expired token")
    args = parser.parse_args()
    try:
        print(create_token(args.user, -5 if args.expired else args.minutes))
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
