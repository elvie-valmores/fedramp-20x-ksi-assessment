"""Tests for SDR-CSX-KMT's metrics, on synthetic run records.

Run with: python -m unittest sdr/test_metrics.py  (from the repository root,
or `python -m unittest test_metrics.py` from sdr/)

Three rules the metrics rest on, each with a case that breaks it:
only scheduled CI runs count, one data point per day (that day's latest),
and windows say how many days actually had data.
"""

import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

import emit


def _run(started, runtime, statuses):
    return {
        "started_at": started,
        "run": {"runtime": runtime},
        "outcomes": [
            {"check": {"id": cid, "indicator": "KSI-X"}, "status": st} for cid, st in statuses.items()
        ],
    }


class Metrics(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        records = {
            "a.json": _run("2026-10-01T05:30:00+00:00", "ci", {"c1": "PASS", "c2": "FAIL"}),
            # Later the same day: this one is the day's data point.
            "b.json": _run("2026-10-01T09:00:00+00:00", "ci", {"c1": "PASS", "c2": "PASS"}),
            "c.json": _run("2026-10-02T05:30:00+00:00", "ci", {"c1": "ERROR", "c2": "PASS"}),
            # A workstation run must never count.
            "d.json": _run("2026-10-03T05:30:00+00:00", "local", {"c1": "FAIL", "c2": "FAIL"}),
        }
        for name, rec in records.items():
            (self.dir / name).write_text(json.dumps(rec))
        self.history = emit.load_history(self.dir)

    def test_only_ci_runs(self):
        self.assertEqual(sorted(self.history), [date(2026, 10, 1), date(2026, 10, 2)])

    def test_latest_run_per_day(self):
        self.assertEqual(self.history[date(2026, 10, 1)]["started_at"], "2026-10-01T09:00:00+00:00")

    def test_summary_and_daily_data(self):
        e = emit.metrics_evidence("KSI-X", self.history, date(2026, 10, 2))
        self.assertEqual(e["evidenceType"], "Report")
        self.assertIn("data on 2 of 30 days", e["evidenceDescription"])
        self.assertIn("every check passed on 1 of 2", e["evidenceDescription"])
        self.assertIn("c1 on 1 day(s)", e["evidenceDescription"])
        self.assertIn("2026-10-01: 2/2 passed", e["evidenceText"])
        self.assertIn("2026-10-02: 1/2 passed (not passing: c1)", e["evidenceText"])

    def test_not_standing_is_not_judged(self):
        # A torn-down environment is neither a pass nor an error that day.
        run = _run("2026-10-04T05:30:00+00:00", "ci", {"c1": "PASS", "c2": "NOT_STANDING"})
        counts = emit._day_counts(run, "KSI-X")
        self.assertEqual((counts["checks"], counts["passed"], counts["errored"], counts["not_standing"]), (1, 1, 0, 1))
        self.assertEqual(counts["not_passing"], [])
        # Only NOT_STANDING: no data point that day, rather than a 0 of 0.
        self.assertIsNone(emit._day_counts(_run("2026-10-04T05:30:00+00:00", "ci", {"c2": "NOT_STANDING"}), "KSI-X"))

    def test_no_data_no_object(self):
        self.assertIsNone(emit.metrics_evidence("KSI-NONE", self.history, date(2026, 10, 2)))


if __name__ == "__main__":
    unittest.main()
