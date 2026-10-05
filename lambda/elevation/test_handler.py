"""The elevation's pure judgements: what is refused, and what the backstop removes."""

import os
import unittest
from datetime import datetime, timedelta, timezone

for name in ("LOG_BUCKET", "ALERT_TOPIC_ARN", "INSTANCE_ARN", "PERMISSION_SET_ARN", "ACCOUNT_ID"):
    os.environ.setdefault(name, "test")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from handler import MAX_AGE, Rejected, sweep_decision, validate  # noqa: E402

NOW = datetime(2026, 10, 3, 12, tzinfo=timezone.utc)
ASSIGNED = [{"PrincipalId": "user-1", "PrincipalType": "USER"}]


def execution(age: timedelta) -> dict:
    return {"executionArn": f"arn:exec:{age}", "startDate": NOW - age}


class Validate(unittest.TestCase):
    def test_accepts_a_justified_request_with_the_default_window(self):
        self.assertEqual(validate({"justification": "apply the retention change, PR 42"}),
                         ("apply the retention change, PR 42", 60))

    def test_refuses_a_short_justification(self):
        with self.assertRaises(Rejected):
            validate({"justification": "fix stuff"})

    def test_refuses_a_missing_justification(self):
        with self.assertRaises(Rejected):
            validate({"minutes": 30})

    def test_refuses_a_window_past_the_longest(self):
        with self.assertRaises(Rejected):
            validate({"justification": "x" * 20, "minutes": 241})

    def test_refuses_a_window_below_the_shortest(self):
        with self.assertRaises(Rejected):
            validate({"justification": "x" * 20, "minutes": 5})

    def test_refuses_a_window_that_is_not_a_whole_number(self):
        for minutes in ("60", 60.5, True):
            with self.assertRaises(Rejected):
                validate({"justification": "x" * 20, "minutes": minutes})


class Sweep(unittest.TestCase):
    def test_leaves_an_assignment_a_running_elevation_holds(self):
        self.assertEqual(sweep_decision(ASSIGNED, [execution(timedelta(minutes=30))], NOW), ([], []))

    def test_removes_an_assignment_nothing_accounts_for(self):
        self.assertEqual(sweep_decision(ASSIGNED, [], NOW), ([], ASSIGNED))

    def test_stops_an_overdue_elevation_and_removes_what_it_held(self):
        overdue = execution(MAX_AGE + timedelta(minutes=1))
        self.assertEqual(sweep_decision(ASSIGNED, [overdue], NOW), ([overdue], ASSIGNED))

    def test_does_nothing_when_nothing_is_assigned(self):
        self.assertEqual(sweep_decision([], [], NOW), ([], []))


if __name__ == "__main__":
    unittest.main()
