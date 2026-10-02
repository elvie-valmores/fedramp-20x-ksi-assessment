"""Tests for the worker's high-water mark (DECISIONS.md, 2026-10-02).

Hermetic: boto3, botocore and the database module are replaced before main
is imported, so these run on a bare interpreter, in CI before the image is
built. The fakes model only what the mark depends on -- a listing in key
order, a write that can fail, and a table whose rows become visible when
they commit, which is not always the order they were stamped in.

Run from app/: python -m unittest worker.test_main
"""

import json
import sys
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


class BotoCoreError(Exception):
    pass


class ClientError(Exception):
    pass


class DatabaseUnavailable(RuntimeError):
    pass


class FakeS3:
    def __init__(self):
        self.objects: dict[str, bytes] = {}
        # Every successful write, in order. Counted rather than read off the
        # object set: two writes in the same second with the same mark share
        # a key, and the second would look like no write at all.
        self.puts: list[str] = []
        self.fail_puts = 0
        self.fail_lists = False

    def get_paginator(self, name):
        assert name == "list_objects_v2"
        return self

    def paginate(self, Bucket, Prefix):
        if self.fail_lists:
            raise ClientError("AccessDenied")
        keys = sorted(k for k in self.objects if k.startswith(Prefix))
        # Two pages, so the newest key is not on the first one.
        half = len(keys) // 2
        return [{"Contents": [{"Key": k} for k in keys[:half]]}, {"Contents": [{"Key": k} for k in keys[half:]]}]

    def put_object(self, Bucket, Key, Body, **kwargs):
        assert kwargs["ServerSideEncryption"] == "aws:kms"
        if self.fail_puts:
            self.fail_puts -= 1
            raise ClientError("ServiceUnavailable")
        self.objects[Key] = Body
        self.puts.append(Key)

    def landed_ids(self, key):
        return [json.loads(line)["id"] for line in self.objects[key].decode().splitlines()]


class FakeDB:
    """A measurements table with a clock. A row is visible once committed."""

    def __init__(self):
        self.clock = datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc)
        self.rows: list[dict] = []
        self.down = False
        self.queries = 0

    def insert(self, id, stamped_ago=timedelta(0), committed=True):
        self.rows.append({"id": id, "recorded_at": self.clock - stamped_ago, "committed": committed})

    def commit(self, id):
        next(r for r in self.rows if r["id"] == id)["committed"] = True

    def connect(self):
        db = self

        class Conn:
            def __enter__(self):
                if db.down:
                    raise DatabaseUnavailable("database unavailable")
                return self

            def __exit__(self, *exc):
                return False

            def execute(self, sql, params=()):
                db.queries += 1
                if sql == "SELECT now()":
                    return Result([(db.clock,)])
                visible = [r for r in db.rows if r["committed"]]
                if "WHERE recorded_at > %s" in sql:
                    visible = [r for r in visible if r["recorded_at"] > params[0]]
                visible.sort(key=lambda r: r["recorded_at"])
                return Result([(r["id"], "acme", "latency_ms", 1.0, r["recorded_at"]) for r in visible])

        return Conn()


class Result:
    def __init__(self, rows):
        self.rows = rows

    def fetchone(self):
        return self.rows[0]

    def fetchall(self):
        return self.rows


S3 = FakeS3()
sys.modules["boto3"] = types.SimpleNamespace(client=lambda name, region_name=None: S3)
sys.modules["botocore"] = types.ModuleType("botocore")
sys.modules["botocore.exceptions"] = types.SimpleNamespace(BotoCoreError=BotoCoreError, ClientError=ClientError)
sys.modules["common"] = types.ModuleType("common")
sys.modules["common.db"] = types.SimpleNamespace(connect=None, DatabaseUnavailable=DatabaseUnavailable)
sys.path.insert(0, str(Path(__file__).parent))

import main  # noqa: E402

main.os.environ.setdefault("EXTRACT_KMS_KEY_ARN", "arn:aws:kms:us-east-1:000000000000:key/test")


class Mark(unittest.TestCase):
    def setUp(self):
        S3.__init__()
        self.db = FakeDB()
        main.connect = self.db.connect

    def cycle(self, after=timedelta(minutes=15)):
        """Advance the database clock one interval and run a cycle; the keys written."""
        self.db.clock += after
        before = len(S3.puts)
        main.cycle("bucket", "measurements", "us-east-1")
        return S3.puts[before:]

    def test_failed_landing_is_retried_after_the_overlap(self):
        # The defect: with a window, rows a failed landing carried were
        # gone from the window by the next cycle. With the mark, they wait.
        self.db.insert(1)
        self.assertEqual(len(self.cycle()), 1)
        self.db.insert(2)
        self.db.insert(3)
        S3.fail_puts = 1
        self.assertEqual(self.cycle(), [])
        # Thirty minutes on, rows 2 and 3 are well past any overlap.
        (key,) = self.cycle()
        self.assertEqual(S3.landed_ids(key), [2, 3])

    def test_nothing_new_lands_nothing(self):
        # A mark at the newest row would re-read that row every cycle and
        # land a duplicate forever. The mark is the time read through, so
        # once the overlap has passed there is nothing to read.
        self.db.insert(1)
        self.assertEqual(len(self.cycle()), 1)
        self.assertEqual(self.cycle(), [])
        self.assertEqual(self.cycle(), [])

    def test_late_commit_within_overlap_is_landed(self):
        # Stamped before the mark, committed after the extract: the overlap
        # is what catches it.
        self.db.insert(1)
        self.db.insert(2, stamped_ago=timedelta(minutes=-14), committed=False)
        (first,) = self.cycle()
        self.assertEqual(S3.landed_ids(first), [1])
        self.db.commit(2)
        (second,) = self.cycle(after=timedelta(minutes=1))
        self.assertIn(2, S3.landed_ids(second))

    def test_mark_is_the_database_clock(self):
        self.db.insert(1)
        (key,) = self.cycle()
        self.assertTrue(key.endswith(f"-through-{self.db.clock:%Y%m%dT%H%M%SZ}.ndjson"), key)
        self.assertEqual(main.landed_mark("bucket", "measurements", "us-east-1"), self.db.clock)

    def test_no_mark_reads_everything(self):
        # First ever cycle, and a prefix holding only extracts landed before
        # marks existed: neither carries a mark, so every row is read.
        S3.objects["measurements/dt=2026-10-01/measurements-20261001T000000Z.ndjson"] = b""
        self.db.insert(1, stamped_ago=timedelta(days=1))
        self.db.insert(2)
        (key,) = self.cycle()
        self.assertEqual(S3.landed_ids(key), [1, 2])

    def test_unmarked_newest_key_does_not_hide_an_older_mark(self):
        self.db.insert(1)
        self.cycle()
        S3.objects["measurements/dt=2099-01-01/measurements-20990101T000000Z.ndjson"] = b""
        self.assertEqual(main.landed_mark("bucket", "measurements", "us-east-1"), self.db.clock)

    def test_unreadable_mark_skips_the_cycle(self):
        # Without the mark, any start point is a guess, and a late guess
        # loses rows. The cycle neither queries nor lands.
        self.db.insert(1)
        S3.fail_lists = True
        self.assertEqual(self.cycle(), [])
        self.assertEqual(self.db.queries, 0)
        S3.fail_lists = False
        self.assertEqual(len(self.cycle()), 1)

    def test_database_down_keeps_the_mark(self):
        self.db.insert(1)
        self.db.down = True
        self.assertEqual(self.cycle(), [])
        self.db.down = False
        self.db.clock += timedelta(hours=2)
        (key,) = self.cycle()
        self.assertEqual(S3.landed_ids(key), [1])


if __name__ == "__main__":
    unittest.main()
