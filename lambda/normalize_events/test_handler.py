"""Tests for the normalizer's classification, against real CloudTrail records.

Run with: python -m unittest lambda/normalize_events/test_handler.py

Written on 2026-10-01, when the detection Lambda returned zero matches over
a window containing two failed Identity Center sign-ins. The normalizer
filed them as API Activity, and as successes. Each case below would have
caught one of the two faults, and both are run against a deliberately
broken classifier too, so a test that passes everything is noticed.
"""

import json
import os
import pathlib
import unittest
from unittest import mock

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
import handler  # noqa: E402  (boto3 client is created at import)

FIXTURES = json.loads((pathlib.Path(__file__).parent / "fixtures.json").read_text())

# (fixture, class_name, status) -- what the detection query depends on.
EXPECTED = [
    ("idp_login_failure", "Authentication", "Failure"),
    ("user_authentication_success", "Authentication", "Success"),
    ("console_login_success", "Authentication", "Success"),
    ("console_login_failure", "Authentication", "Failure"),
]


def classify(record):
    out = handler._to_ocsf(record, "437672023758")
    return out["class_name"], out["status"]


class Classification(unittest.TestCase):
    def test_sign_ins(self):
        for name, cls, status in EXPECTED:
            with self.subTest(name):
                self.assertEqual(classify(FIXTURES[name]), (cls, status))

    def test_failure_carries_its_reason(self):
        out = handler._to_ocsf(FIXTURES["idp_login_failure"], "437672023758")
        self.assertEqual(out["status_detail"], "Responses must contain exactly one Assertion")

    def test_identity_center_user_is_named(self):
        out = handler._to_ocsf(FIXTURES["user_authentication_success"], "437672023758")
        self.assertEqual(out["actor"]["user"]["name"], "14a83458-a031-70ba-43d2-5a551fd66c1e")

    def test_ordinary_api_error_still_fails(self):
        record = {"eventName": "GetLoginProfile", "errorCode": "NoSuchEntity"}
        self.assertEqual(classify(record), ("API Activity", "Failure"))


class NegativeControls(unittest.TestCase):
    """The two faults of 2026-10-01, reintroduced. The tests above must fail."""

    def _caught(self):
        result = unittest.TestResult()
        unittest.defaultTestLoader.loadTestsFromTestCase(Classification).run(result)
        return not result.wasSuccessful()

    def test_errorcode_only_status_is_caught(self):
        with mock.patch.object(handler, "_failed", lambda r: bool(r.get("errorCode"))):
            self.assertTrue(self._caught())

    def test_missing_identity_center_events_are_caught(self):
        narrowed = handler.AUTH_EVENT_NAMES - {"ExternalIdPDirectoryLogin", "UserAuthentication"}
        with mock.patch.object(handler, "AUTH_EVENT_NAMES", narrowed):
            self.assertTrue(self._caught())


if __name__ == "__main__":
    unittest.main()
