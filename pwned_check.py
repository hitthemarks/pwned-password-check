#!/usr/bin/env python3
"""Check a password against Have I Been Pwned's Pwned Passwords dataset.

Uses the k-anonymity range API: only the first 5 hex characters of the
SHA-1 hash are sent. Matching happens locally. Standard library only.

Exit codes: 0 = not found, 1 = found in breaches, 2 = no input, 3 = lookup failed
"""

import getpass
import hashlib
import sys
import urllib.error
import urllib.request

API = "https://api.pwnedpasswords.com/range/"


def pwned_count(password: str) -> int:
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    req = urllib.request.Request(
        API + prefix,
        headers={
            "Add-Padding": "true",          # hides real response size from traffic observers
            "User-Agent": "pwned-check-script",
        },
    )
    with urllib.request.urlopen(req, timeout=10) as res:
        body = res.read().decode("utf-8")

    for line in body.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return int(count)              # padded rows have count 0, so they never trigger
    return 0


def main() -> int:
    try:
        pw = getpass.getpass("Password to check (input hidden): ")
    except (KeyboardInterrupt, EOFError):
        print()
        return 2

    if not pw:
        print("No password entered.")
        return 2

    try:
        n = pwned_count(pw)
    except urllib.error.URLError as e:
        print(f"Lookup failed: {e}", file=sys.stderr)
        return 3

    if n:
        print(f"Seen {n:,} times in breaches. Change it.")
        return 1
    print("Not found in the dataset.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
