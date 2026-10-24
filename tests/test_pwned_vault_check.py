"""Tests for pwned_vault_check.

A fake `op` executable is put at the front of PATH, so no real 1Password
account is touched. fetch_range is patched, so no network calls are made.
All item and vault names are made up.
"""

import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pwned_vault_check  # noqa: E402

SHARED_PW = "shared-test-password-1"
UNIQUE_PW = "unique-test-password-2"

ITEMS = [
    {
        "id": "item1",
        "title": "Example Forum",
        "vault": {"id": "v1", "name": "Personal"},
        "password": SHARED_PW,
    },
    {
        "id": "item2",
        "title": "Demo Shop",
        "vault": {"id": "v2", "name": "Shared"},
        "password": SHARED_PW,
    },
    {
        "id": "item3",
        "title": "Sample Router",
        "vault": {"id": "v1", "name": "Personal"},
        "password": UNIQUE_PW,
    },
    {
        "id": "item4",
        "title": "Placeholder Wiki",
        "vault": {"id": "v1", "name": "Personal"},
        "password": None,
    },
]

# Fake op: answers `item list` and `item get <id>` from a JSON file next to it.
FAKE_OP = """#!{python}
import json, os, sys

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "items.json")) as f:
    items = json.load(f)

args = sys.argv[1:]
if args[:2] == ["item", "list"]:
    print(json.dumps([
        {{"id": i["id"], "title": i["title"], "vault": i["vault"]}} for i in items
    ]))
elif args[:2] == ["item", "get"]:
    item = next((i for i in items if i["id"] == args[2]), None)
    if item is None or item.get("fail"):
        sys.stderr.write("[ERROR] item not found\\n")
        sys.exit(1)
    fields = [{{"id": "username", "purpose": "USERNAME", "value": "someone"}}]
    if item["password"] is not None:
        fields.append(
            {{"id": "password", "purpose": "PASSWORD", "value": item["password"]}}
        )
    print(json.dumps({{"id": item["id"], "title": item["title"], "fields": fields}}))
else:
    sys.stderr.write("[ERROR] unexpected arguments\\n")
    sys.exit(1)
"""


def sha1(pw: str) -> str:
    return hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()


class FakeOpTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        op_path = os.path.join(self.tmp.name, "op")
        with open(op_path, "w") as f:
            f.write(FAKE_OP.format(python=sys.executable))
        os.chmod(op_path, 0o755)
        self.write_items(ITEMS)
        patcher = mock.patch.dict(
            os.environ, {"PATH": self.tmp.name + os.pathsep + os.environ["PATH"]}
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def write_items(self, items):
        with open(os.path.join(self.tmp.name, "items.json"), "w") as f:
            json.dump(items, f)

    def run_main(self, breached=None, fetch_side_effect=None):
        """Run main() with fetch_range patched.

        breached maps a password to the count the fake API reports for it.
        """
        breached = breached or {}

        def fake_fetch(prefix):
            return {
                sha1(pw)[5:]: n
                for pw, n in breached.items()
                if sha1(pw)[:5] == prefix
            }

        out, err = io.StringIO(), io.StringIO()
        with (
            mock.patch.object(
                pwned_vault_check,
                "fetch_range",
                side_effect=fetch_side_effect or fake_fetch,
            ) as fetch,
            redirect_stdout(out),
            redirect_stderr(err),
        ):
            code = pwned_vault_check.main()
        self.fetch = fetch
        return code, out.getvalue(), err.getvalue()


class VaultCheckTests(FakeOpTestCase):
    def test_breached_shared_password(self):
        code, out, err = self.run_main(breached={SHARED_PW: 321})

        self.assertEqual(code, 1)

        # Breached list: both logins that share the breached password.
        self.assertIn("2 logins use a breached password", out)
        self.assertIn("321  Demo Shop [Shared]", out)
        self.assertIn("321  Example Forum [Personal]", out)
        self.assertNotIn("Sample Router", out.split("shared by")[0])

        # Reuse report.
        self.assertIn("1 password is shared by more than one login", out)
        self.assertIn("2 logins: Example Forum [Personal], Demo Shop [Shared]", out)

        # Summary counts: 4 items, 1 without a password, 2 unique passwords.
        self.assertIn(
            "Checked 3 logins (2 unique passwords). 1 had no password, 0 skipped.",
            out,
        )

    def test_each_prefix_is_queried_once(self):
        self.run_main()
        prefixes = [c.args[0] for c in self.fetch.call_args_list]
        expected = {sha1(SHARED_PW)[:5], sha1(UNIQUE_PW)[:5]}
        self.assertEqual(sorted(prefixes), sorted(expected))
        self.assertEqual(len(prefixes), len(set(prefixes)))

    def test_clean_vault_exits_0_but_still_reports_reuse(self):
        code, out, _ = self.run_main()
        self.assertEqual(code, 0)
        self.assertIn("No breached passwords found.", out)
        self.assertIn("1 password is shared by more than one login", out)

    def test_passwords_and_hashes_are_never_printed(self):
        _, out, err = self.run_main(breached={SHARED_PW: 5, UNIQUE_PW: 9})
        for pw in (SHARED_PW, UNIQUE_PW):
            self.assertNotIn(pw, out + err)
            self.assertNotIn(sha1(pw), out + err)
            self.assertNotIn(sha1(pw)[5:], out + err)

    def test_lookup_failure_exits_3(self):
        code, _, err = self.run_main(
            fetch_side_effect=urllib.error.URLError("offline")
        )
        self.assertEqual(code, 3)
        self.assertIn("Lookup failed", err)

    def test_failing_item_is_skipped(self):
        broken = {
            "id": "item5",
            "title": "Broken Item",
            "vault": {"id": "v1", "name": "Personal"},
            "password": "never-read",
            "fail": True,
        }
        self.write_items(ITEMS + [broken])
        code, out, err = self.run_main()
        self.assertEqual(code, 0)
        self.assertIn("skipped Broken Item [Personal]", err)
        self.assertIn("1 had no password, 1 skipped.", out)


class OpErrorTests(unittest.TestCase):
    def test_op_missing_exits_3(self):
        with tempfile.TemporaryDirectory() as empty:
            err = io.StringIO()
            with (
                mock.patch.dict(os.environ, {"PATH": empty}),
                redirect_stdout(io.StringIO()),
                redirect_stderr(err),
            ):
                code = pwned_vault_check.main()
        self.assertEqual(code, 3)
        self.assertIn("op not found", err.getvalue())


class FetchRangeTests(unittest.TestCase):
    def test_zero_count_padding_rows_are_dropped(self):
        body = "\r\n".join(["A" * 35 + ":10", "B" * 35 + ":0", "C" * 35 + ":2"])
        res = mock.MagicMock()
        res.read.return_value = body.encode("utf-8")
        res.__enter__.return_value = res
        with mock.patch("urllib.request.urlopen", return_value=res) as urlopen:
            counts = pwned_vault_check.fetch_range("ABCDE")
        self.assertEqual(counts, {"A" * 35: 10, "C" * 35: 2})
        req = urlopen.call_args.args[0]
        self.assertEqual(req.full_url, pwned_vault_check.API + "ABCDE")
        self.assertEqual(req.get_header("Add-padding"), "true")


if __name__ == "__main__":
    unittest.main()
