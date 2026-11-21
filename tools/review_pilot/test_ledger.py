"""Synthetic fixtures. Exercise local storage without repository or model access."""

import hashlib
import json
import multiprocessing
import sqlite3
import tempfile
from contextlib import closing
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Barrier

from ledger import MAX_DIFF_BYTES, MAX_FIELD_BYTES, CI, Finding, Ledger, Package, Review


def fixture(revision=1, line=10):
    head = f"{revision:040x}"
    path = "synthetic/example.txt"
    diff = (
        f"--- a/{path}\n+++ b/{path}\n@@ -{line} +{line} @@\n-old\n+new\n"
    ).encode()
    package = Package(1, "a" * 40, head, (CI(revision, head, "success"),), diff)
    finding = Finding(
        "correctness", "state.cleanup", "State remains set", "Operation cancels",
        head, path, line, "Synthetic fixture expects state to reset",
    )
    return package, (
        Review("correctness", "complete", (finding, finding)),
        Review("defensive-security", "complete", (replace(finding, reviewer="defensive-security"),)),
    )


def initialize_process(barrier):
    global process_barrier
    process_barrier = barrier


def submit_process(directory, revision):
    ledger = Ledger(directory)
    package, reviews = fixture(revision)
    process_barrier.wait(timeout=10)
    try:
        return ledger.record(package, reviews, current_head=package.head, opted_in=True)
    except ValueError as error:
        if str(error) != "three-round limit reached":
            raise
        return 0


class LedgerTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name) / "private"
        self.ledger = Ledger(self.directory)

    def record(self, package, reviews):
        return self.ledger.record(package, reviews, current_head=package.head, opted_in=True)

    def test_opt_in_and_private_storage(self):
        package, reviews = fixture()
        with self.assertRaises(PermissionError):
            self.ledger.record(package, reviews, current_head=package.head)
        self.assertEqual(self.ledger.findings(1), {})
        self.assertEqual(self.directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.ledger.path.stat().st_mode & 0o777, 0o600)
        self.directory.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "private"):
            Ledger(self.directory)

    def test_frozen_package_and_idempotency(self):
        package, reviews = fixture()
        self.assertEqual(self.record(package, reviews), 1)
        self.assertEqual(self.record(package, reviews), 1)
        with self.assertRaisesRegex(ValueError, "frozen"):
            self.record(replace(package, ci=()), reviews)

    def test_diff_digest_and_manifest_frozen_with_package(self):
        package, reviews = fixture()
        self.record(package, reviews)
        with closing(sqlite3.connect(self.ledger.path)) as db:
            encoded, = db.execute("SELECT package FROM rounds").fetchone()
        frozen = json.loads(encoded)
        digest = frozen.pop("package_sha256")
        canonical = json.dumps(frozen, sort_keys=True, separators=(",", ":")).encode()
        self.assertEqual(digest, hashlib.sha256(canonical).hexdigest())
        self.assertEqual(frozen["provenance"], "operator_asserted")
        self.assertEqual(frozen["diff_sha256"], hashlib.sha256(package.diff).hexdigest())
        self.assertEqual(frozen["manifest"], {"synthetic/example.txt": [10]})
        self.assertNotIn("+new", encoded)
        with self.assertRaisesRegex(ValueError, "frozen"):
            self.record(replace(package, diff=package.diff.replace(b"+new", b"+other")), reviews)

    def test_manifest_uses_new_side_coordinates(self):
        package, reviews = fixture()
        diff = (
            b"--- a/synthetic/example.txt\n+++ b/synthetic/example.txt\n"
            b"@@ -10,2 +20 @@\n keep\n-removed\n"
            b"@@ -30 +40,2 @@\n-old\n+new\n+extra\n"
        )
        package = replace(package, diff=diff)
        original = reviews[0].findings[0]
        for line in (10, 21, 30, 39, 42):
            with self.subTest(line=line), self.assertRaisesRegex(ValueError, "pinned manifest"):
                self.record(package, (replace(reviews[0], findings=(replace(original, line=line),)),
                                      reviews[1]))
        valid = tuple(replace(original, line=line, root_cause=f"state.line{line}") for line in (20, 40, 41))
        self.assertEqual(self.record(package, (replace(reviews[0], findings=valid),
                                              replace(reviews[1], findings=()))), 1)

    def test_overlapping_or_backward_old_ranges_rejected(self):
        package, reviews = fixture()
        for old_start in (9, 10, 11):
            diff = (
                b"--- a/synthetic/example.txt\n+++ b/synthetic/example.txt\n"
                b"@@ -10,2 +10 @@\n-old\n-removed\n+new\n"
                + f"@@ -{old_start} +20 @@\n-old\n+new\n".encode()
            )
            with self.subTest(old_start=old_start), self.assertRaisesRegex(ValueError, "old-side"):
                self.record(replace(package, diff=diff), reviews)

    def test_existing_ledger_path_replacement_rejected(self):
        self.ledger.path.rename(self.directory / "original")
        self.ledger.path.touch(mode=0o600)
        with self.assertRaisesRegex(ValueError, "identity changed"):
            self.ledger.findings(1)

    def test_invalid_diff_and_field_limits(self):
        package, reviews = fixture()
        for diff in (
            b"x" * (MAX_DIFF_BYTES + 1),
            b"\xff",
            package.diff.replace(b"@@ -10 +10 @@", b"@@ -10 +10,2 @@"),
            package.diff + b"\nextra",
            package.diff.replace(b"+10 @@", b"+10,999999999 @@"),
            package.diff.replace(b"synthetic/", b"../"),
        ):
            with self.subTest(length=len(diff)), self.assertRaises(ValueError):
                self.record(replace(package, diff=diff), reviews)

        original = reviews[0].findings[0]
        for fields in (
            {"failure": "x" * (MAX_FIELD_BYTES + 1)},
            {"trigger": "é" * MAX_FIELD_BYTES},
            {"evidence": "bad\x00input"},
            {"root_cause": "x" * 97},
            {"head": "b" * 40},
            {"path": "synthetic/other.txt"},
        ):
            with self.subTest(field=next(iter(fields))), self.assertRaisesRegex(ValueError, "finding"):
                self.record(package, (replace(reviews[0], findings=(replace(original, **fields),)),
                                      reviews[1]))
        self.assertEqual(self.record(package, reviews), 1)

    def test_dedupe_attribution_and_anchor_refresh(self):
        self.record(*fixture())
        self.record(*fixture(2, 20))
        findings = self.ledger.findings(1)
        self.assertEqual(list(findings), ["state.cleanup"])
        self.assertEqual({f.finding.reviewer for f in findings["state.cleanup"]},
                         {"correctness", "defensive-security"})
        self.assertEqual([f.finding.line for f in findings["state.cleanup"]], [20, 20])

    def test_same_head_result_retry_and_conflict(self):
        package, reviews = fixture()
        self.record(package, reviews)
        single = replace(reviews[0], findings=reviews[0].findings[:1])
        self.assertEqual(self.record(package, (reviews[1], single)), 1)
        different = replace(single.findings[0], evidence="Different fixture evidence")
        for changed in (replace(single, findings=(different,)), Review("correctness", "timeout")):
            with self.assertRaisesRegex(ValueError, "frozen review results"):
                self.record(package, (changed, reviews[1]))

    def test_clean_or_incomplete_round_marks_prior_evidence_historical(self):
        for pr, status in enumerate(("complete", "timeout", "disabled"), 1):
            with self.subTest(status=status):
                package, reviews = fixture()
                self.record(replace(package, pr=pr), reviews)
                self.assertEqual({f.status for f in self.ledger.findings(pr)["state.cleanup"]},
                                 {"current"})
                package, _ = fixture(2)
                self.record(replace(package, pr=pr), (Review("correctness", "complete"),
                                                     Review("defensive-security", status)))
                self.assertEqual({f.status for f in self.ledger.findings(pr)["state.cleanup"]},
                                 {"historical"})
                package, reviews = fixture(3, 20)
                self.record(replace(package, pr=pr), reviews)
                evidence = self.ledger.findings(pr)["state.cleanup"]
                self.assertEqual({(f.status, f.round) for f in evidence}, {("current", 3)})

    def test_multiprocess_contention(self):
        from concurrent.futures import ProcessPoolExecutor

        context = multiprocessing.get_context("spawn")
        with ProcessPoolExecutor(
            4, mp_context=context, initializer=initialize_process, initargs=(context.Barrier(4),)
        ) as executor:
            for revisions, expected in (([1] * 4, [1] * 4), ([2, 3, 4, 5], [0, 0, 2, 3])):
                tasks = [executor.submit(submit_process, self.directory, revision)
                         for revision in revisions]
                self.assertEqual(sorted(task.result(timeout=15) for task in tasks), expected)

    def test_finding_write_failure_rolls_back_round_and_prior_updates(self):
        self.record(*fixture())
        with closing(sqlite3.connect(self.ledger.path)) as db, db:
            db.execute("""
                CREATE TRIGGER fixture_failure BEFORE INSERT ON findings
                WHEN NEW.reviewer = 'defensive-security'
                BEGIN SELECT RAISE(ABORT, 'fixture write failure'); END
            """)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "fixture write failure"):
            self.record(*fixture(2, 20))
        evidence = self.ledger.findings(1)["state.cleanup"]
        self.assertEqual({(item.round, item.finding.line) for item in evidence}, {(1, 10)})
        with closing(sqlite3.connect(self.ledger.path)) as db, db:
            db.execute("DROP TRIGGER fixture_failure")
        self.assertEqual(self.record(*fixture(2, 20)), 2)

    def test_stale_or_malformed_input(self):
        package, reviews = fixture()
        with self.assertRaisesRegex(ValueError, "current head"):
            self.ledger.record(package, reviews, current_head="b" * 40, opted_in=True)
        invalid_finding = replace(reviews[0].findings[0], line=999)
        for invalid_package, invalid_reviews in (
            (replace(package, base="deadbeef"), reviews),
            (replace(package, ci=(CI(1, "b" * 40, "success"),)), reviews),
            (package, (replace(reviews[0], findings=(invalid_finding,)), reviews[1])),
            (package, (replace(reviews[0], status="timeout"), reviews[1])),
        ):
            with self.subTest(package=invalid_package, reviews=invalid_reviews):
                with self.assertRaises(ValueError):
                    self.record(invalid_package, invalid_reviews)
        self.assertEqual(self.record(package, reviews), 1)

    def test_missing_ci_and_review_outcomes(self):
        for revision, status in enumerate(("timeout", "invalid", "disabled"), 1):
            package, _ = fixture(revision)
            round_number = self.record(replace(package, ci=()), (
                Review("correctness", status),
                Review("defensive-security", "complete"),
            ))
            self.assertEqual(round_number, revision)
        self.assertEqual(self.ledger.findings(1), {})
        with closing(sqlite3.connect(self.ledger.path)) as db:
            rows = db.execute("SELECT package, outcomes FROM rounds ORDER BY round").fetchall()
        self.assertEqual([json.loads(row[0])["ci"] for row in rows], [[], [], []])
        self.assertEqual([json.loads(row[1])["statuses"]["correctness"] for row in rows],
                         ["timeout", "invalid", "disabled"])

    def test_concurrent_retry_and_cap(self):
        for revisions, expected in (([1] * 4, [1] * 4), ([2, 3, 4, 5], [0, 0, 2, 3])):
            barrier = Barrier(len(revisions))

            def submit(revision):
                barrier.wait()
                try:
                    return self.record(*fixture(revision))
                except ValueError as error:
                    if str(error) != "three-round limit reached":
                        raise
                    return 0

            with ThreadPoolExecutor(len(revisions)) as executor:
                self.assertEqual(sorted(executor.map(submit, revisions)), expected)
        with self.assertRaisesRegex(ValueError, "three-round limit"):
            self.record(*fixture(6))


if __name__ == "__main__":
    unittest.main()
