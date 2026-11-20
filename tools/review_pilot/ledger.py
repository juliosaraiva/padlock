"""Local shadow-review records. Standard library only. No reviewer adapter."""

import hashlib
import json
import os
import re
import secrets
import sqlite3
from contextlib import closing, contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from stat import S_ISDIR, S_ISREG
from typing import Literal


@dataclass(frozen=True)
class CI:
    run_id: int
    head: str
    conclusion: Literal["success", "failure", "cancelled", "pending"]


@dataclass(frozen=True)
class Package:
    pr: int
    base: str
    head: str
    ci: tuple[CI, ...]
    diff: bytes  # Sanitized unified diff. Only its digest and manifest are persisted.


@dataclass(frozen=True)
class Finding:
    reviewer: Literal["correctness", "defensive-security"]
    root_cause: str
    failure: str
    trigger: str
    head: str
    path: str
    line: int
    evidence: str


@dataclass(frozen=True)
class Review:
    reviewer: Literal["correctness", "defensive-security"]
    status: Literal["complete", "timeout", "invalid", "disabled"]
    findings: tuple[Finding, ...] = ()


REVIEWERS = {"correctness", "defensive-security"}


MAX_DIFF_BYTES = 256 * 1024
MAX_HUNK_LINES = 4096
MAX_CI_RUNS = 64
MAX_FINDINGS = 64
MAX_FIELD_BYTES = 2048
PATH = r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*"
HUNK = re.compile(r"@@ -(\d{1,9})(?:,(\d{1,9}))? \+(\d{1,9})(?:,(\d{1,9}))? @@")


def manifest(diff: bytes) -> dict[str, set[int]]:
    """Derive eligible new-side lines from a bounded, plain unified text diff."""
    if type(diff) is not bytes or not 0 < len(diff) <= MAX_DIFF_BYTES:
        raise ValueError("diff must contain 1 to 262144 bytes")
    try:
        lines = iter(diff.decode("utf-8").split("\n"))
    except UnicodeDecodeError as error:
        raise ValueError("diff must be UTF-8") from error

    files: dict[str, set[int]] = {}
    current = next(lines)
    while current:
        old = re.fullmatch(r"--- (?:a/(" + PATH + r")|/dev/null)", current)
        new = re.fullmatch(r"\+\+\+ b/(" + PATH + r")", next(lines, ""))
        if old is None or new is None:
            raise ValueError("expected plain unified diff file headers")
        path = new[1]
        if (
            len(path) > 256 or path in files or {".", ".."} & set(path.split("/"))
            or old[1] not in (None, path)
        ):
            raise ValueError("invalid or duplicate diff path")
        anchors = files[path] = set()
        current = next(lines, "")
        if HUNK.fullmatch(current) is None:
            raise ValueError("file requires a unified diff hunk")

        old_end = new_end = 0
        while match := HUNK.fullmatch(current):
            old_position, old_count, start, count = match.groups()
            old_start = int(old_position)
            old_left = int(old_count or "1")
            new_left = int(count or "1")
            line = int(start)
            if max(old_left, new_left) > MAX_HUNK_LINES or not (old_left or new_left):
                raise ValueError("hunk must contain 1 to 4096 lines per nonempty side")
            # Empty ranges identify the position after their stated line.
            old_first = old_start + (old_left == 0)
            new_first = line + (new_left == 0)
            if old_first < max(1, old_end):
                raise ValueError("invalid, backward or overlapping old-side range")
            if new_first < max(1, new_end):
                raise ValueError("invalid, backward or overlapping new-side range")
            old_end = old_first + old_left
            new_end = new_first + new_left
            while old_left or new_left:
                row = next(lines, "")
                if not row or row[0] not in " +-":
                    raise ValueError("diff hunk body does not match its header")
                if row[0] != "+":
                    old_left -= 1
                if row[0] != "-":
                    anchors.add(line)
                    line += 1
                    new_left -= 1
                if old_left < 0 or new_left < 0:
                    raise ValueError("diff hunk line count exceeded")
            current = next(lines, "")

    if not files or next(lines, None) is not None:
        raise ValueError("empty diff or unexpected trailing content")
    return files


def valid_text(value: str) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= MAX_FIELD_BYTES
        and bool(value.strip())
        and value.isprintable()
        and len(value.encode("utf-8")) <= MAX_FIELD_BYTES
    )


def validate(package: Package, reviews: tuple[Review, ...]) -> dict[str, set[int]]:
    if type(package.pr) is not int or not 0 < package.pr < 2**63 or any(
        not isinstance(sha, str) or len(sha) != 40 or not re.fullmatch(r"[0-9a-f]{40}", sha)
        for sha in (package.base, package.head)
    ):
        raise ValueError("invalid PR or commit SHA")
    if not isinstance(package.ci, tuple) or len(package.ci) > MAX_CI_RUNS:
        raise ValueError("too many CI runs")
    runs = set()
    for run in package.ci:
        if (
            not isinstance(run, CI)
            or run.head != package.head
            or type(run.run_id) is not int
            or not 0 < run.run_id < 2**63
            or run.run_id in runs
            or run.conclusion not in ("success", "failure", "cancelled", "pending")
        ):
            raise ValueError("invalid or stale CI evidence")
        runs.add(run.run_id)

    anchors = manifest(package.diff)
    if (
        not isinstance(reviews, tuple)
        or len(reviews) != len(REVIEWERS)
        or any(not isinstance(review, Review) for review in reviews)
        or any(sum(r.reviewer == reviewer for r in reviews) != 1 for reviewer in REVIEWERS)
    ):
        raise ValueError("one result per reviewer required")
    for review in reviews:
        if review.status not in ("complete", "timeout", "invalid", "disabled"):
            raise ValueError("invalid reviewer status")
        if review.status != "complete" and review.findings:
            raise ValueError("findings require a completed review")
        if not isinstance(review.findings, tuple) or len(review.findings) > MAX_FINDINGS:
            raise ValueError("too many findings")
        for finding in review.findings:
            if (
                not isinstance(finding, Finding)
                or finding.reviewer != review.reviewer
                or finding.head != package.head
                or not isinstance(finding.path, str)
                or len(finding.path) > 256
                or type(finding.line) is not int
                or finding.line not in anchors.get(finding.path, ())
                or not isinstance(finding.root_cause, str)
                or len(finding.root_cause) > 96
                or not re.fullmatch(r"[a-z0-9]+(?:[._-][a-z0-9]+)*", finding.root_cause)
                or not all(
                    valid_text(field)
                    for field in (finding.failure, finding.trigger, finding.evidence)
                )
            ):
                raise ValueError("invalid finding fields or anchor outside pinned manifest")
    return anchors


@dataclass(frozen=True)
class FindingRecord:
    finding: Finding
    round: int
    status: Literal["current", "historical"]


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def frozen_package(package: Package, anchors: dict[str, set[int]]) -> str:
    pinned = {
        "provenance": "operator_asserted",
        "pr": package.pr,
        "base": package.base,
        "head": package.head,
        "ci": [asdict(run) for run in sorted(package.ci, key=lambda run: run.run_id)],
        "diff_sha256": hashlib.sha256(package.diff).hexdigest(),
        "manifest": {path: sorted(lines) for path, lines in anchors.items()},
    }
    pinned["package_sha256"] = hashlib.sha256(canonical_json(pinned).encode()).hexdigest()
    return canonical_json(pinned)


def canonical_findings(review: Review) -> dict:
    by_cause = {}
    for finding in review.findings:
        entry = asdict(finding)
        if by_cause.setdefault(finding.root_cause, entry) != entry:
            raise ValueError("conflicting findings for one reviewer and root cause")
    return by_cause


class Ledger:
    """One ledger per repository, under an operator-controlled stable directory.

    The directory and its ancestry must stay stable and protected from path
    replacement. Same-UID processes and privileged users are trusted. SQLite
    opens by pathname and the mode checks do not defend against a racing rename.
    Package provenance is operator asserted. The manifest describes supplied
    hunk coordinates, without verifying them against Git objects or CI records.
    """

    def __init__(self, directory: Path):
        directory.mkdir(mode=0o700, exist_ok=True)
        stat = directory.lstat()
        if not S_ISDIR(stat.st_mode) or stat.st_uid != os.getuid() or stat.st_mode & 0o077:
            raise ValueError("ledger requires a private owner-only directory")
        self.directory = directory.resolve(strict=True)
        self.directory_identity = (stat.st_dev, stat.st_ino)
        self.path = self.directory / "ledger.sqlite3"
        # Create with a private mode before SQLite opens it.
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            stat = os.fstat(fd)
            if not S_ISREG(stat.st_mode) or stat.st_uid != os.getuid() or stat.st_mode & 0o077:
                raise ValueError("ledger requires an owner-only database")
            self.file_identity = (stat.st_dev, stat.st_ino)
        finally:
            os.close(fd)

        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS rounds (
                    pr INTEGER NOT NULL,
                    round INTEGER NOT NULL CHECK (round BETWEEN 1 AND 3),
                    head TEXT NOT NULL,
                    package TEXT NOT NULL,
                    outcomes TEXT NOT NULL,
                    PRIMARY KEY (pr, round),
                    UNIQUE (pr, head)
                );
                CREATE TABLE IF NOT EXISTS api_attempts (
                    pr INTEGER NOT NULL,
                    head TEXT NOT NULL,
                    ceiling_microusd INTEGER NOT NULL CHECK (ceiling_microusd > 0),
                    package TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    attempt_id TEXT NOT NULL,
                    PRIMARY KEY (pr, head)
                );
                CREATE TABLE IF NOT EXISTS findings (
                    pr INTEGER NOT NULL,
                    root_cause TEXT NOT NULL,
                    reviewer TEXT NOT NULL,
                    latest_round INTEGER NOT NULL,
                    finding TEXT NOT NULL,
                    PRIMARY KEY (pr, root_cause, reviewer)
                );
            """)

    def check_path(self) -> None:
        for path, identity, expected_type in (
            (self.directory, self.directory_identity, S_ISDIR),
            (self.path, self.file_identity, S_ISREG),
        ):
            stat = path.lstat()
            if (
                (stat.st_dev, stat.st_ino) != identity
                or not expected_type(stat.st_mode)
                or stat.st_uid != os.getuid()
                or stat.st_mode & 0o077
            ):
                raise ValueError("private ledger path identity changed")

    @contextmanager
    def connect(self):
        self.check_path()
        with closing(sqlite3.connect(f"{self.path.as_uri()}?mode=rw", uri=True)) as db:
            self.check_path()
            yield db

    def used_heads(self, db, pr: int) -> set[str]:
        rows = db.execute(
            "SELECT head FROM rounds WHERE pr = ? UNION SELECT head FROM api_attempts WHERE pr = ?",
            (pr, pr),
        )
        return {head for (head,) in rows}

    def reserve_api_attempt(
        self, package: Package, request_digest: str, ceiling: int, budget: int
    ) -> str:
        snapshot = frozen_package(package, manifest(package.diff))
        attempt_id = secrets.token_hex(32)
        # Keep reservations after failure or interruption, since the provider may bill.
        with self.connect() as db, db:
            db.execute("BEGIN IMMEDIATE")
            heads = self.used_heads(db, package.pr)
            if package.head in heads:
                raise ValueError("head already reviewed or reserved")
            if len(heads) >= 3:
                raise ValueError("three-round limit reached")
            spent = db.execute(
                "SELECT COALESCE(SUM(ceiling_microusd), 0) FROM api_attempts WHERE pr = ?",
                (package.pr,),
            ).fetchone()[0]
            if spent + ceiling > budget:
                raise ValueError("PR cost cap reached")
            db.execute(
                "INSERT INTO api_attempts VALUES (?, ?, ?, ?, ?, ?)",
                (package.pr, package.head, ceiling, snapshot, request_digest, attempt_id),
            )
        return attempt_id

    def record(
        self,
        package: Package,
        reviews: tuple[Review, ...],
        *,
        current_head: str,
        opted_in: bool = False,
        api_attempt: tuple[str, str] | None = None,
    ) -> int:
        if opted_in is not True:
            raise PermissionError("explicit pilot opt-in required")
        if not isinstance(package, Package):
            raise ValueError("invalid package")
        if package.head != current_head:
            raise ValueError("package does not match operator-supplied current head")
        anchors = validate(package, reviews)
        serialized = frozen_package(package, anchors)
        results = {
            review.reviewer: {"status": review.status, "findings": canonical_findings(review)}
            for review in reviews
        }
        outcomes = canonical_json({
            "statuses": {review.reviewer: review.status for review in reviews},
            "result_sha256": hashlib.sha256(canonical_json(results).encode()).hexdigest(),
        })

        with self.connect() as db, db:
            db.execute("BEGIN IMMEDIATE")
            reservation = db.execute(
                "SELECT package, attempt_id, request_digest FROM api_attempts WHERE pr = ? AND head = ?",
                (package.pr, package.head),
            ).fetchone()
            if reservation is None:
                if api_attempt is not None:
                    raise ValueError("missing API reservation")
            elif api_attempt is None or reservation != (serialized, *api_attempt):
                raise ValueError("API finalization does not match reserved attempt and package")
            prior = db.execute(
                "SELECT round, package, outcomes FROM rounds WHERE pr = ? AND head = ?",
                (package.pr, package.head),
            ).fetchone()
            if prior:
                if prior[1] != serialized:
                    raise ValueError("head already has a different frozen package")
                if prior[2] != outcomes:
                    raise ValueError("head already has different frozen review results")
                return prior[0]

            heads = self.used_heads(db, package.pr)
            if package.head not in heads and len(heads) >= 3:
                raise ValueError("three-round limit reached")
            number = db.execute(
                "SELECT COUNT(*) FROM rounds WHERE pr = ?", (package.pr,)
            ).fetchone()[0] + 1
            if number > 3:
                raise ValueError("three-round limit reached")

            db.execute(
                "INSERT INTO rounds VALUES (?, ?, ?, ?, ?)",
                (package.pr, number, package.head, serialized, outcomes),
            )
            for reviewer, result in results.items():
                for root_cause, finding in result["findings"].items():
                    db.execute(
                        """
                        INSERT INTO findings VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT (pr, root_cause, reviewer) DO UPDATE SET
                            latest_round = excluded.latest_round,
                            finding = excluded.finding
                        """,
                        (package.pr, root_cause, reviewer, number, canonical_json(finding)),
                    )
            return number

    def findings(self, pr: int) -> dict[str, list[FindingRecord]]:
        """Group reviewer evidence and mark evidence from earlier rounds historical."""
        with self.connect() as db:
            rows = db.execute(
                """
                SELECT root_cause, finding, latest_round,
                       latest_round = (SELECT MAX(round) FROM rounds WHERE pr = ?)
                FROM findings WHERE pr = ?
                ORDER BY root_cause, latest_round DESC, reviewer
                """,
                (pr, pr),
            ).fetchall()
        grouped: dict[str, list[FindingRecord]] = {}
        for root_cause, finding, number, current in rows:
            record = FindingRecord(
                Finding(**json.loads(finding)), number, "current" if current else "historical"
            )
            grouped.setdefault(root_cause, []).append(record)
        return grouped
