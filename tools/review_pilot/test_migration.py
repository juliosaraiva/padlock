"""Independent SQLite fixtures for the previously shipped schema layouts."""

import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import asdict
from pathlib import Path
from threading import Barrier
from unittest.mock import patch

import anthropic_adapter as adapter
from ledger import Ledger
from test_anthropic_adapter import response
from test_ledger import fixture


HISTORY = """
CREATE TABLE rounds (
    pr INTEGER NOT NULL, round INTEGER NOT NULL CHECK (round BETWEEN 1 AND 3),
    head TEXT NOT NULL, package TEXT NOT NULL, outcomes TEXT NOT NULL,
    PRIMARY KEY (pr, round), UNIQUE (pr, head)
);
CREATE TABLE findings (
    pr INTEGER NOT NULL, root_cause TEXT NOT NULL, reviewer TEXT NOT NULL,
    latest_round INTEGER NOT NULL, finding TEXT NOT NULL,
    PRIMARY KEY (pr, root_cause, reviewer)
);
"""
ATTEMPTS = """
CREATE TABLE api_attempts (
    pr INTEGER NOT NULL, head TEXT NOT NULL,
    ceiling_microusd INTEGER NOT NULL CHECK (ceiling_microusd > 0),
    {binding}
    PRIMARY KEY (pr, head)
);
"""
BINDING = "package TEXT NOT NULL, request_digest TEXT NOT NULL, attempt_id TEXT NOT NULL,"


class MigrationTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.home = Path(temp.name)
        self.directory = self.home / ".padlock-review-pilot"
        self.directory.mkdir(mode=0o700)
        self.path = self.directory / "ledger.sqlite3"

    def open_db(self):
        return closing(sqlite3.connect(self.path))

    def old_layout(self, shape):
        package, reviews = fixture()
        finding = reviews[0].findings[0]
        with self.open_db() as db, db:
            db.executescript(HISTORY)
            db.execute("INSERT INTO rounds VALUES (?, 1, ?, '{}', '{}')",
                       (package.pr, package.head))
            db.execute("INSERT INTO findings VALUES (?, ?, ?, 1, ?)", (
                package.pr, finding.root_cause, finding.reviewer, json.dumps(asdict(finding)),
            ))
            if shape == "legacy":
                db.executescript(ATTEMPTS.format(binding=""))
                db.executemany("INSERT INTO api_attempts VALUES (?, ?, ?)", (
                    (1, fixture(2)[0].head, 750_000),
                    (2, fixture()[0].head, 1_400_000),
                ))
            elif shape == "unversioned":
                db.executescript(ATTEMPTS.format(binding=BINDING))
                db.execute("INSERT INTO api_attempts VALUES (?, ?, ?, ?, ?, ?)", (
                    1, fixture(2)[0].head, 300_000, "snapshot", "digest", "attempt",
                ))
        self.path.chmod(0o600)

    def history(self):
        with self.open_db() as db:
            return tuple(db.execute(f"SELECT * FROM {table}").fetchall()
                         for table in ("rounds", "findings"))

    def test_fresh_ledger_and_reopen(self):
        Ledger(self.directory)
        original = self.path.read_bytes()
        Ledger(self.directory)
        self.assertEqual(self.path.read_bytes(), original)
        with self.open_db() as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone(), (1,))

    def test_offline_history_preserved(self):
        self.old_layout("offline")
        before = self.history()
        ledger = Ledger(self.directory)
        self.assertEqual(self.history(), before)
        self.assertEqual(ledger.findings(1)["state.cleanup"][0].status, "current")
        package, _ = fixture(2)
        ledger.reserve_api_attempt(package, "digest", 100, adapter.BUDGET_MICROUSD)

    def test_spent_history_cost_and_rounds_preserved(self):
        self.old_layout("legacy")
        before = self.history()
        ledger = Ledger(self.directory)
        self.assertEqual(self.history(), before)
        with self.open_db() as db:
            self.assertEqual(db.execute(
                "SELECT pr, ceiling_microusd, state FROM api_attempts ORDER BY pr"
            ).fetchall(), [(1, 750_000, "legacy_spent"), (2, 1_400_000, "legacy_spent")])
        package, reviews = fixture(2)
        with self.assertRaisesRegex(ValueError, "reviewed or reserved"):
            ledger.reserve_api_attempt(package, "digest", 100, adapter.BUDGET_MICROUSD)
        with self.assertRaisesRegex(ValueError, "spent and cannot finalize"):
            ledger.record(package, reviews, current_head=package.head, opted_in=True)
        with self.assertRaisesRegex(ValueError, "cost cap"):
            ledger.reserve_api_attempt(fixture(3)[0], "digest", 750_001, adapter.BUDGET_MICROUSD)
        ledger.reserve_api_attempt(fixture(3)[0], "digest", 750_000, adapter.BUDGET_MICROUSD)
        with self.assertRaisesRegex(ValueError, "three-round"):
            ledger.reserve_api_attempt(fixture(4)[0], "digest", 1, adapter.BUDGET_MICROUSD)

    def test_unversioned_binding_preserved_under_concurrent_open(self):
        self.old_layout("unversioned")
        before = self.history()
        barrier = Barrier(4)

        def open_ledger(_):
            barrier.wait(timeout=5)
            Ledger(self.directory)

        with ThreadPoolExecutor(4) as pool:
            list(pool.map(open_ledger, range(4)))
        self.assertEqual(self.history(), before)
        with self.open_db() as db:
            self.assertEqual(db.execute("""
                SELECT ceiling_microusd, package, request_digest, attempt_id, state
                FROM api_attempts
            """).fetchall(), [(300_000, "snapshot", "digest", "attempt", "reserved")])

    def test_failure_rolls_back_schema_history_and_version(self):
        self.old_layout("legacy")
        before = self.path.read_bytes()
        prepare = Ledger.prepare_schema

        def interrupt(ledger, db):
            prepare(ledger, db)
            raise sqlite3.OperationalError("fixture interruption before commit")

        with patch.object(Ledger, "prepare_schema", interrupt):
            with self.assertRaisesRegex(ValueError, "schema check failed"):
                Ledger(self.directory)
        self.assertEqual(self.path.read_bytes(), before)
        Ledger(self.directory)

    def cli_args(self, package):
        metadata = self.home / "metadata.json"
        metadata.write_text(json.dumps({
            "repo": adapter.REPO, "pr": package.pr, "base": package.base, "head": package.head,
            "ci": [asdict(run) for run in package.ci],
        }))
        diff = self.home / "fixture.diff"
        diff.write_bytes(package.diff)
        digest = adapter.request_digest(adapter.requests_for(package))
        return [
            "adapter", "--metadata", str(metadata), "--diff", str(diff),
            "--current-head", package.head, "--approve-public-sanitized-package-sha256", digest,
        ]

    def call_cli(self, package, return_value):
        with (
            patch("sys.argv", self.cli_args(package)),
            patch("sys.stdin.isatty", return_value=True),
            patch("sys.stderr.isatty", return_value=True),
            patch("sys.stderr.write"),
            patch("builtins.print"),
            patch.object(Path, "home", return_value=self.home),
            patch.object(adapter, "hidden_key", return_value="fixture_key") as key,
            patch.object(adapter, "send", return_value=response(package)) as transport,
        ):
            self.assertEqual(adapter.main(), return_value)
        return key, transport

    def test_bad_schema_stops_before_key_or_send_and_preserves_file(self):
        for shape in ("partial", "unknown", "newer", "corrupt"):
            with self.subTest(shape=shape):
                if shape == "corrupt":
                    self.path.write_bytes(b"not a SQLite database")
                else:
                    with self.open_db() as db, db:
                        if shape == "partial":
                            db.execute("CREATE TABLE rounds (pr INTEGER)")
                        else:
                            db.executescript(HISTORY)
                            if shape == "newer":
                                db.execute("PRAGMA user_version = 99")
                            else:
                                db.execute("CREATE TABLE unexpected (id INTEGER)")
                self.path.chmod(0o600)
                before = self.path.read_bytes()
                key, transport = self.call_cli(fixture(2)[0], 1)
                key.assert_not_called()
                transport.assert_not_called()
                self.assertEqual(self.path.read_bytes(), before)
                self.path.unlink()

    def test_inconsistent_index_stops_before_key_or_send(self):
        self.old_layout("legacy")
        with self.open_db() as db, db:
            indexes = db.execute("""
                SELECT name, rootpage FROM sqlite_schema
                WHERE tbl_name = 'rounds' AND type = 'index'
                ORDER BY name
            """).fetchall()
            (first, first_page), (second, second_page) = indexes
            # Both B-trees stay readable, but their entries describe different keys.
            db.execute("PRAGMA writable_schema = ON")
            db.executemany("UPDATE sqlite_schema SET rootpage = ? WHERE name = ?", (
                (second_page, first), (first_page, second),
            ))
            db.execute("PRAGMA writable_schema = OFF")

        with self.open_db() as db:
            self.assertEqual(db.execute("PRAGMA quick_check").fetchall(), [("ok",)])
            problems = db.execute("PRAGMA integrity_check").fetchall()
        self.assertTrue(any("index" in problem for (problem,) in problems), problems)

        before = self.path.read_bytes()
        with self.assertRaisesRegex(ValueError, "ledger integrity check failed"):
            Ledger(self.directory)
        key, transport = self.call_cli(fixture(3)[0], 1)
        key.assert_not_called()
        transport.assert_not_called()
        self.assertEqual(self.path.read_bytes(), before)

    def test_supported_startup_reaches_only_mock_transport(self):
        self.old_layout("offline")
        key, transport = self.call_cli(fixture(2)[0], 0)
        key.assert_called_once()
        self.assertEqual(transport.call_count, 2)
