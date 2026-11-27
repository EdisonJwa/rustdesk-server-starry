#!/usr/bin/env python3
"""Fail closed on the defect class that shipped a vulnerability in this session.

The production bug was not a typo: it was a *predicate shape*. The address book
selected rows with `owner_id = ?1 or rule >= 1`, where `rule` is the book's share
ceiling rather than a grant, so the second half was always true and every
signed-in account could read every book.

The test suite was green because every e2e used a single account: "can A see B's
data" was not expressible. So the durable fix is two things, and this gate is the
second one — a check that the shape cannot come back.

## What this checks

A query that reads `ab_books` and decides *access* must either

- be ownership-only (`owner_id = ?N` and nothing else in the predicate), or
- join `ab_shares`.

An `ab_books` query that tests `rule >=` in its `where` clause without joining
`ab_shares` is the exact shipped defect and is rejected, because `rule` is a
ceiling that never identifies *who* may read.

## What this deliberately does not check

Whether the predicate is *correct* in some deeper sense. That needs a human and
the multi-account e2e tests, which is where this belongs. This gate only stops the
specific shape from returning.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# A whole SQL statement, from select to the end of its Rust literal.
QUERY = re.compile(r'"((?:select|insert|update|delete)[^"]*)"', re.IGNORECASE | re.DOTALL)


def rust_files() -> list[Path]:
    return sorted((ROOT / "src").rglob("*.rs"))


def ab_books_queries(text: str) -> list[str]:
    return [
        match.group(1)
        for match in QUERY.finditer(text)
        if re.search(r"\bfrom\s+ab_books\b", match.group(1), re.IGNORECASE)
    ]


def check_access_predicates() -> list[str]:
    problems: list[str] = []
    for path in rust_files():
        text = path.read_text(encoding="utf-8")
        line_of = lambda offset: text.count("\n", 0, offset) + 1
        for match in QUERY.finditer(text):
            query = match.group(1)
            if not re.search(r"\bfrom\s+ab_books\b", query, re.IGNORECASE):
                continue
            lowered = " ".join(query.lower().split())

            # Ownership by itself is fine.
            ownership_only = re.search(
                r"where\s+\(?\s*owner_id\s*=\s*\?\w+", lowered
            ) and not re.search(r"\bor\b", lowered.split("where", 1)[-1])

            if "ab_shares" in lowered:
                continue
            if ownership_only:
                continue
            # A query that names `rule` as an access alternative is the defect.
            if re.search(r"\brule\s*>=", lowered):
                problems.append(
                    f"{path.relative_to(ROOT)}:{line_of(match.start())}: "
                    "an ab_books query gates access on `rule`, which is the book's "
                    "share ceiling and not a grant. Visibility must be ownership or "
                    f"an ab_shares row. Query: {lowered[:180]}"
                )
    return problems


def main() -> int:
    problems = check_access_predicates()
    if problems:
        print("address book access rules violated:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print("address book access OK: every ab_books predicate is ownership or a share")
    return 0


if __name__ == "__main__":
    sys.exit(main())
