"""Regression tests for HTTP Digest qop selection."""

import hashlib
import unittest

from requests import auth
from requests.utils import parse_dict_header


class TestDigestQop(unittest.TestCase):
    def header(self, qop, algorithm="MD5"):
        a = auth.HTTPDigestAuth("user", "pass")
        a.init_per_thread_state()
        challenge = f'realm="demo", nonce="nonce", algorithm="{algorithm}"'
        if qop is not None:
            challenge += f', qop="{qop}"'
        a._thread_local.chal = parse_dict_header(challenge)
        return a.build_digest_header("GET", "https://example.test/private?x=1")

    def test_supported_options(self):
        for qop in (
            "auth",
            "auth-int,auth",
            "auth-int, auth",
            "auth, auth-int",
            "auth-int,\tauth",
            "auth-int,  auth\t",
            "other, auth , auth-int",
        ):
            with self.subTest(qop=qop):
                header = self.header(qop)
                self.assertIsNotNone(header)
                parts = parse_dict_header(header.removeprefix("Digest "))
                self.assertEqual(parts["qop"], "auth")
                self.assertEqual(parts["uri"], "/private?x=1")

                def md5(value):
                    return hashlib.md5(
                        value.encode(), usedforsecurity=False
                    ).hexdigest()

                ha1 = md5("user:demo:pass")
                ha2 = md5("GET:/private?x=1")
                expected = md5(
                    f"{ha1}:nonce:{parts['nc']}:{parts['cnonce']}:auth:{ha2}"
                )
                self.assertEqual(parts["response"], expected)

    def test_unsupported_options(self):
        for qop in (
            "auth-int",
            "auth-int, other",
            "oauth",
            "xauth",
            "AUTH",
            "auth-int,auth-extra",
        ):
            with self.subTest(qop=qop):
                self.assertIsNone(self.header(qop))

    def test_omitted_qop(self):
        for qop in (None, ""):
            with self.subTest(qop=qop):
                header = self.header(qop)
                self.assertIsNotNone(header)
                self.assertNotIn(
                    "qop", parse_dict_header(header.removeprefix("Digest "))
                )

    def test_algorithms(self):
        for algorithm in ("MD5", "MD5-SESS", "SHA", "SHA-256", "SHA-512"):
            with self.subTest(algorithm=algorithm):
                self.assertIsNotNone(self.header("auth-int, auth", algorithm))
