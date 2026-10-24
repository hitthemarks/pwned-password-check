"""Tests for pwned_check. The API is mocked; no network calls are made."""

import hashlib
import io
import os
import sys
import unittest
import urllib.error
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pwned_check  # noqa: E402

PASSWORD = "correct-horse-test-only"
SHA1 = hashlib.sha1(PASSWORD.encode("utf-8")).hexdigest().upper()
PREFIX, SUFFIX = SHA1[:5], SHA1[5:]


def fake_response(body: str) -> mock.MagicMock:
    """Return an object that behaves like urlopen's context manager."""
    res = mock.MagicMock()
    res.read.return_value = body.encode("utf-8")
    res.__enter__.return_value = res
    return res


class PwnedCountTests(unittest.TestCase):
    def test_found_returns_count(self):
        body = "\r\n".join(["0" * 35 + ":3", SUFFIX + ":1234", "F" * 35 + ":7"])
        with mock.patch("urllib.request.urlopen", return_value=fake_response(body)):
            self.assertEqual(pwned_check.pwned_count(PASSWORD), 1234)

    def test_not_found_returns_zero(self):
        body = "\r\n".join(["0" * 35 + ":3", "F" * 35 + ":7"])
        with mock.patch("urllib.request.urlopen", return_value=fake_response(body)):
            self.assertEqual(pwned_check.pwned_count(PASSWORD), 0)

    def test_padded_row_with_zero_count_is_not_a_match(self):
        body = "\r\n".join(["0" * 35 + ":3", SUFFIX + ":0"])
        with mock.patch("urllib.request.urlopen", return_value=fake_response(body)):
            self.assertEqual(pwned_check.pwned_count(PASSWORD), 0)

    def test_sends_only_prefix_with_padding_header(self):
        with mock.patch(
            "urllib.request.urlopen", return_value=fake_response("")
        ) as urlopen:
            pwned_check.pwned_count(PASSWORD)
        req = urlopen.call_args.args[0]
        self.assertEqual(req.full_url, pwned_check.API + PREFIX)
        self.assertNotIn(SUFFIX, req.full_url)
        self.assertNotIn(PASSWORD, req.full_url)
        self.assertEqual(req.get_header("Add-padding"), "true")
        self.assertIsNotNone(urlopen.call_args.kwargs.get("timeout"))


class MainTests(unittest.TestCase):
    def run_main(self, password=PASSWORD, urlopen_kwargs=None):
        out, err = io.StringIO(), io.StringIO()
        with (
            mock.patch("getpass.getpass", return_value=password),
            mock.patch("urllib.request.urlopen", **(urlopen_kwargs or {})),
            redirect_stdout(out),
            redirect_stderr(err),
        ):
            code = pwned_check.main()
        return code, out.getvalue(), err.getvalue()

    def test_found_exits_1(self):
        body = SUFFIX + ":42"
        code, out, _ = self.run_main(
            urlopen_kwargs={"return_value": fake_response(body)}
        )
        self.assertEqual(code, 1)
        self.assertIn("Seen 42 times", out)

    def test_not_found_exits_0(self):
        code, out, _ = self.run_main(
            urlopen_kwargs={"return_value": fake_response("0" * 35 + ":1")}
        )
        self.assertEqual(code, 0)
        self.assertIn("Not found", out)

    def test_padded_zero_row_exits_0(self):
        code, _, _ = self.run_main(
            urlopen_kwargs={"return_value": fake_response(SUFFIX + ":0")}
        )
        self.assertEqual(code, 0)

    def test_lookup_failure_exits_3(self):
        code, out, err = self.run_main(
            urlopen_kwargs={"side_effect": urllib.error.URLError("offline")}
        )
        self.assertEqual(code, 3)
        self.assertIn("Lookup failed", err)
        self.assertNotIn(PASSWORD, out + err)

    def test_empty_input_exits_2(self):
        code, _, _ = self.run_main(password="")
        self.assertEqual(code, 2)

    def test_password_is_never_printed(self):
        _, out, err = self.run_main(
            urlopen_kwargs={"return_value": fake_response(SUFFIX + ":5")}
        )
        self.assertNotIn(PASSWORD, out + err)


if __name__ == "__main__":
    unittest.main()
