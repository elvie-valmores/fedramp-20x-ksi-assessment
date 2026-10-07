"""Negative controls for the matrix link validator (sdr/matrix_rows.py).

Each case is a link that must be refused, beside the sound version that
must pass, so a validator that accepted everything would fail here.

    cd sdr && ../.venv/bin/python -m unittest test_matrix_rows.py
"""

import copy
import unittest

from matrix_rows import coverage, link_problems

ROWS = [{"id": "KSI-AAA-BBB.verify.1"}, {"id": "KSI-AAA-BBB.validate.1"}]


def check(cid, **fields):
    return {"id": cid, **fields}


SOUND = [
    check("a", matrix_rows=[{"row": "KSI-AAA-BBB.verify.1", "covers": "full", "with": ["b"]}]),
    check("b", matrix_rows=[{"row": "KSI-AAA-BBB.verify.1", "covers": "full", "with": ["a"]}]),
    check("c", matrix_rows=[{"row": "KSI-AAA-BBB.validate.1", "covers": "partial", "gap": "one cloud"}]),
    check("d", unlinked_reason="proves a build row"),
]


class Links(unittest.TestCase):
    def assertRefused(self, checks, fragment):
        problems = link_problems(checks, ROWS)
        self.assertTrue(any(fragment in p for p in problems), problems)

    def broken(self, index, **change):
        checks = copy.deepcopy(SOUND)
        checks[index].update(change)
        return checks

    def test_sound_links_pass(self):
        self.assertEqual(link_problems(SOUND, ROWS), [])

    def test_row_the_matrix_lacks(self):
        self.assertRefused(self.broken(2, matrix_rows=[{"row": "KSI-AAA-BBB.verify.9", "covers": "partial", "gap": "x"}]),
                           "the matrix does not have")

    def test_partial_without_gap(self):
        self.assertRefused(self.broken(2, matrix_rows=[{"row": "KSI-AAA-BBB.validate.1", "covers": "partial"}]),
                           "must say what is missing")

    def test_unknown_covers(self):
        self.assertRefused(self.broken(2, matrix_rows=[{"row": "KSI-AAA-BBB.validate.1", "covers": "mostly"}]),
                           "covers must be")

    def test_neither_links_nor_reason(self):
        self.assertRefused(self.broken(3, unlinked_reason=""), "exactly one of")

    def test_both_links_and_reason(self):
        self.assertRefused(self.broken(2, unlinked_reason="also this"), "exactly one of")

    def test_group_not_named_back(self):
        # b claims full with a, but a does not name b: a one-sided group
        # would let one check claim a row it proves only half of.
        checks = self.broken(0, matrix_rows=[{"row": "KSI-AAA-BBB.verify.1", "covers": "full"}])
        self.assertRefused(checks, "without naming b")

    def test_group_member_missing(self):
        self.assertRefused(self.broken(0, matrix_rows=[{"row": "KSI-AAA-BBB.verify.1", "covers": "full", "with": ["b", "z"]}]),
                           "names z")


class Coverage(unittest.TestCase):
    def test_statuses(self):
        cov = coverage(SOUND, ROWS)
        self.assertEqual(cov["KSI-AAA-BBB.verify.1"]["status"], "full")
        self.assertEqual(cov["KSI-AAA-BBB.validate.1"]["status"], "partial")

    def test_full_outranks_partial(self):
        checks = SOUND + [check("e", matrix_rows=[{"row": "KSI-AAA-BBB.validate.1", "covers": "full"}])]
        self.assertEqual(coverage(checks, ROWS)["KSI-AAA-BBB.validate.1"]["status"], "full")


if __name__ == "__main__":
    unittest.main()


class Positions(unittest.TestCase):
    """Recorded positions for rows no check covers (2026-10-06)."""

    ROWS = [{"id": "K.verify.1", "indicator": "K"}, {"id": "K.verify.2", "indicator": "K"}]
    CHECK = {"id": "c", "matrix_rows": [{"row": "K.verify.1", "covers": "full"}]}
    GOOD = {"position": "gap", "reason": "r", "risk": "k"}

    def cov(self, positions):
        from matrix_rows import coverage
        return coverage([self.CHECK], self.ROWS, positions)

    def test_a_position_records_an_uncovered_row(self):
        from matrix_rows import position_problems
        cov = self.cov({"K.verify.2": self.GOOD})
        self.assertEqual(cov["K.verify.2"]["status"], "recorded")
        self.assertEqual(position_problems({"K.verify.2": self.GOOD}, self.cov({})), [])

    def test_a_position_on_a_covered_row_is_stale(self):
        from matrix_rows import position_problems
        self.assertTrue(position_problems({"K.verify.1": self.GOOD}, self.cov({})))
        self.assertEqual(self.cov({"K.verify.1": self.GOOD})["K.verify.1"]["status"], "full")

    def test_a_position_needs_a_real_row_a_kind_a_reason_and_a_risk(self):
        from matrix_rows import position_problems
        base = self.cov({})
        self.assertTrue(position_problems({"K.verify.9": self.GOOD}, base))
        self.assertTrue(position_problems({"K.verify.2": {**self.GOOD, "position": "later"}}, base))
        self.assertTrue(position_problems({"K.verify.2": {**self.GOOD, "reason": ""}}, base))
        self.assertTrue(position_problems({"K.verify.2": {**self.GOOD, "risk": " "}}, base))

    def test_a_manual_row_says_where_its_evidence_is(self):
        from matrix_rows import position_problems
        base = self.cov({})
        self.assertTrue(position_problems({"K.verify.2": {**self.GOOD, "position": "manual"}}, base))
        self.assertEqual(position_problems({"K.verify.2": {**self.GOOD, "position": "manual", "evidence": "e"}}, base), [])
