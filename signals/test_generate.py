"""The signal computations that are pure: what they count, and what they must not."""

import datetime as dt
import unittest

from generate import check_days, finding_to_fix_days, gate_runs, gates_never_failed, minutes_in, objectives

D = dt.date(2026, 10, 1)


def run(*outcomes):
    return {"outcomes": [{"check": {"id": cid, **extra}, "status": status} for cid, status, extra in outcomes]}


class Gates(unittest.TestCase):
    def test_counts_completed_runs_and_failures(self):
        runs = [{"status": "completed", "conclusion": "success"}, {"status": "completed", "conclusion": "failure"},
                {"status": "in_progress", "conclusion": None}]
        self.assertEqual(gate_runs({"g": runs}), {"g": {"runs": 2, "failed": 1}})

    def test_a_gate_that_never_failed_is_named_and_an_idle_one_is_not(self):
        counts = {"busy": {"runs": 5, "failed": 0}, "caught": {"runs": 5, "failed": 1}, "idle": {"runs": 0, "failed": 0}}
        self.assertEqual(gates_never_failed(counts), ["busy"])


class History(unittest.TestCase):
    def test_finding_to_fix_measures_fail_to_pass(self):
        history = {D: run(("a", "FAIL", {})), D + dt.timedelta(days=3): run(("a", "PASS", {})),
                   D + dt.timedelta(days=4): run(("b", "FAIL", {}))}
        self.assertEqual(finding_to_fix_days(history), {"fixed": 1, "median_days": 3, "max_days": 3, "still_failing": 1})

    def test_no_fixes_is_a_zero_not_an_absence(self):
        self.assertEqual(finding_to_fix_days({}), {"fixed": 0, "median_days": 0, "max_days": 0, "still_failing": 0})

    def test_check_days_ignores_days_not_judged(self):
        history = {D: run(("a", "PASS", {})), D + dt.timedelta(days=1): run(("a", "NOT_STANDING", {})),
                   D + dt.timedelta(days=2): run(("a", "FAIL", {}))}
        self.assertEqual(check_days(history, lambda o: o["check"]["id"] == "a"), {"passed_days": 1, "judged_days": 2})


class Objectives(unittest.TestCase):
    def test_minutes_from_the_declared_prose(self):
        self.assertEqual(minutes_in("60 minutes, restore into a new instance"), 60)
        self.assertEqual(minutes_in("2 hours"), 120)
        self.assertEqual(minutes_in("Immediate: prior versions are read in place"), 0)
        self.assertIsNone(minutes_in("whenever"))

    def test_only_classes_with_a_time_objective_count(self):
        resources = {"classes": {"A": {"objective": {"rto": "5 minutes"}}, "B": {"objective": {"not_applicable": "x"}}}}
        self.assertEqual(objectives(resources), {"A": 5})


if __name__ == "__main__":
    unittest.main()
