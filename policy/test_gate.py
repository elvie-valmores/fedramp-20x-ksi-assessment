"""The gate's own judgements: what blocks, what an exception excuses, and
when the gate must refuse to vouch for a plan."""

import datetime as dt
import unittest

from gate import coverage_problems, exception_problems, judge, scanner_parse_failed, scanner_view

TODAY = dt.date(2026, 10, 5)


def finding(rule="AWS-NET-01", severity="CRITICAL", address="aws_vpc_security_group_ingress_rule.r", root="aws"):
    return {"root": root, "source": "authored", "rule": rule, "address": address,
            "severity": severity, "block_at": "HIGH", "msg": "m"}


def exception(rule="AWS-NET-01", address="aws_vpc_security_group_ingress_rule.r", expires=dt.date(2027, 1, 1), root="aws"):
    return {"rule": rule, "root": root, "address": address, "reason": "r", "expires": expires}


class Judge(unittest.TestCase):
    def test_a_finding_at_the_threshold_blocks(self):
        self.assertEqual(len(judge([finding(severity="HIGH")], [], TODAY)["blocking"]), 1)

    def test_a_finding_below_the_threshold_is_reported_only(self):
        verdict = judge([finding(severity="MEDIUM")], [], TODAY)
        self.assertEqual((len(verdict["blocking"]), len(verdict["reported"])), (0, 1))

    def test_an_exception_excuses_its_finding(self):
        verdict = judge([finding()], [exception()], TODAY)
        self.assertEqual((len(verdict["blocking"]), len(verdict["excepted"])), (0, 1))

    def test_an_expired_exception_does_not(self):
        verdict = judge([finding()], [exception(expires=dt.date(2026, 10, 4))], TODAY)
        self.assertEqual(len(verdict["blocking"]), 1)
        self.assertEqual(len(verdict["expired_exceptions"]), 1)

    def test_an_exception_for_another_address_does_not(self):
        self.assertEqual(len(judge([finding()], [exception(address="other")], TODAY)["blocking"]), 1)

    def test_an_exception_for_another_root_does_not(self):
        self.assertEqual(len(judge([finding()], [exception(root="gcp")], TODAY)["blocking"]), 1)

    def test_an_exception_matching_nothing_is_stale(self):
        self.assertEqual(len(judge([], [exception()], TODAY)["stale_exceptions"]), 1)


class Registers(unittest.TestCase):
    def test_coverage_and_rules_must_agree(self):
        good = {"rules": {"A-B-01": {"severity": "HIGH", "determinations": ["KSI-X"]}}}
        self.assertEqual(coverage_problems({"A-B-01"}, good), [])
        self.assertTrue(coverage_problems({"A-B-01", "A-B-02"}, good))
        self.assertTrue(coverage_problems(set(), good))
        self.assertTrue(coverage_problems({"A-B-01"}, {"rules": {"A-B-01": {"severity": "SEVERE", "determinations": ["K"]}}}))
        self.assertTrue(coverage_problems({"A-B-01"}, {"rules": {"A-B-01": {"severity": "HIGH", "determinations": []}}}))

    def test_an_exception_needs_a_reason_and_an_expiry(self):
        self.assertEqual(exception_problems([exception()]), [])
        self.assertTrue(exception_problems([{**exception(), "reason": ""}]))
        self.assertTrue(exception_problems([{**exception(), "expires": None}]))
        self.assertTrue(exception_problems([{**exception(), "expires": "someday"}]))


class Scanner(unittest.TestCase):
    def test_a_parse_failure_is_caught(self):
        log = '2026-10-05 ERROR [terraform parser] Error parsing file module="root" err="main.tf:10,7-8: Invalid expression"'
        self.assertTrue(scanner_parse_failed(log))

    def test_the_embedded_checks_fallback_is_not_a_failure(self):
        log = '2026-10-05 ERROR [misconfig] Falling back to embedded checks err="failed to check cache"'
        self.assertFalse(scanner_parse_failed(log))

    def test_the_scanner_view_drops_data_sources_only(self):
        plan = {"planned_values": {"root_module": {"resources": [{"mode": "data"}, {"mode": "managed"}],
                                                   "child_modules": [{"resources": [{"mode": "data"}]}]}}}
        view = scanner_view(plan)
        self.assertEqual(view["planned_values"]["root_module"]["resources"], [{"mode": "managed"}])
        self.assertEqual(view["planned_values"]["root_module"]["child_modules"][0]["resources"], [])
        self.assertEqual(len(plan["planned_values"]["root_module"]["resources"]), 2)


if __name__ == "__main__":
    unittest.main()
