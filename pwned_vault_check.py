#!/usr/bin/env python3
"""Check every Login password in 1Password against HIBP Pwned Passwords.

Requires the 1Password CLI (op) with desktop app integration turned on.

Privacy:
  - Passwords are read into memory one at a time, hashed, and discarded.
    Only SHA-1 hashes are kept. Nothing is written to disk.
  - No password is ever printed. Output shows item titles only.
  - Only 5-character hash prefixes are sent to the API, with padding on.
  - Identical passwords share one lookup, so each prefix is queried once.

Exit codes: 0 = nothing breached, 1 = breached passwords found, 3 = error
"""

import hashlib
import json
import subprocess
import sys
import urllib.error
import urllib.request
from collections import defaultdict

API = "https://api.pwnedpasswords.com/range/"


def op_json(*args):
    proc = subprocess.run(
        ["op", *args, "--format", "json"], capture_output=True, text=True
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"op exited {proc.returncode}")
    return json.loads(proc.stdout)


def get_password(item):
    args = ["item", "get", item["id"], "--reveal"]
    vault_id = item.get("vault", {}).get("id")
    if vault_id:
        args += ["--vault", vault_id]
    detail = op_json(*args)
    for field in detail.get("fields", []):
        if field.get("purpose") == "PASSWORD" and field.get("value"):
            return field["value"]
    return None


def fetch_range(prefix):
    req = urllib.request.Request(
        API + prefix,
        headers={"Add-Padding": "true", "User-Agent": "pwned-vault-check"},
    )
    with urllib.request.urlopen(req, timeout=15) as res:
        body = res.read().decode("utf-8")
    counts = {}
    for line in body.splitlines():
        suffix, count = line.split(":")
        n = int(count)
        if n:  # padded rows have count 0
            counts[suffix] = n
    return counts


def label_for(item):
    title = item.get("title") or "(untitled)"
    vault = item.get("vault", {}).get("name") or "?"
    return f"{title} [{vault}]"


def main():
    try:
        items = op_json("item", "list", "--categories", "Login")
    except FileNotFoundError:
        print("op not found. Install the 1Password CLI first.", file=sys.stderr)
        return 3
    except RuntimeError as e:
        print(f"op failed: {e}", file=sys.stderr)
        return 3

    total = len(items)
    print(f"Reading {total} logins from 1Password...", file=sys.stderr)

    by_hash = defaultdict(list)  # full SHA-1 -> list of item labels
    no_password = 0
    skipped = 0

    for i, item in enumerate(items, 1):
        print(f"\r  {i}/{total}", end="", file=sys.stderr, flush=True)
        try:
            pw = get_password(item)
        except (RuntimeError, json.JSONDecodeError) as e:
            print(f"\n  skipped {label_for(item)}: {e}", file=sys.stderr)
            skipped += 1
            continue
        if not pw:
            no_password += 1
            continue
        sha1 = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
        pw = None
        by_hash[sha1].append(label_for(item))
    print(file=sys.stderr)

    by_prefix = defaultdict(list)
    for h in by_hash:
        by_prefix[h[:5]].append(h)

    print(f"Checking {len(by_hash)} unique passwords...", file=sys.stderr)
    hits = []  # (count, label)
    for prefix, hashes in by_prefix.items():
        try:
            counts = fetch_range(prefix)
        except urllib.error.URLError as e:
            print(f"Lookup failed: {e}", file=sys.stderr)
            return 3
        for h in hashes:
            n = counts.get(h[5:])
            if n:
                hits.extend((n, label) for label in by_hash[h])

    print()
    if hits:
        hits.sort(key=lambda x: (-x[0], x[1]))
        noun = "login uses" if len(hits) == 1 else "logins use"
        print(f"{len(hits)} {noun} a breached password (times seen, item):\n")
        for n, label in hits:
            print(f"  {n:>12,}  {label}")
    else:
        print("No breached passwords found.")

    reused = sorted(
        (labels for labels in by_hash.values() if len(labels) > 1),
        key=len,
        reverse=True,
    )
    if reused:
        noun = "password is" if len(reused) == 1 else "passwords are"
        print(f"\n{len(reused)} {noun} shared by more than one login:\n")
        for labels in reused:
            print(f"  {len(labels)} logins: " + ", ".join(labels))

    print(
        f"\nChecked {total - skipped - no_password} logins "
        f"({len(by_hash)} unique passwords). "
        f"{no_password} had no password, {skipped} skipped."
    )
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
