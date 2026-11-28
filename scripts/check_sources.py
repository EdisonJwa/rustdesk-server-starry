#!/usr/bin/env python3
"""Fail closed on the two defect classes that shipped from this repository.

Neither was a typo. Both were shapes that compile and pass tests.

## 1. Address book access predicates

The production bug was `owner_id = ?1 or rule >= 1`, where `rule` is the book's
share ceiling rather than a grant, so the second half was always true and every
signed-in account could read every book. The e2e suite was green because each
test used a single account: "can A see B's data" was not expressible.

A query that reads `ab_books` and decides *access* must either be
ownership-only, or join `ab_shares`.

## 2. Quotes in SQL comments

`SCHEMA` and the inline queries are Rust string literals holding SQL. A quote
inside a SQL comment closes the literal early and the compiler reports a syntax
error dozens of lines from the cause. This cost four compile cycles in one
session; the check exists so it cannot cost a fifth.

## What this deliberately does not check

Whether a predicate is correct in some deeper sense. That needs a human and the
multi-account tests. This gate only stops the known shapes from returning.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# A whole SQL statement, from its verb to the end of the Rust literal.
QUERY = re.compile(r'"((?:select|insert|update|delete)[^"]*)"', re.IGNORECASE | re.DOTALL)


def rust_files() -> list[Path]:
    return sorted((ROOT / "src").rglob("*.rs"))


def check_access_predicates() -> list[str]:
    """An `ab_books` query must gate access on ownership or an `ab_shares` join."""
    problems: list[str] = []
    for path in rust_files():
        text = path.read_text(encoding="utf-8")
        for match in QUERY.finditer(text):
            query = match.group(1)
            if not re.search(r"\bfrom\s+ab_books\b", query, re.IGNORECASE):
                continue
            lowered = " ".join(query.lower().split())
            if "ab_shares" in lowered:
                continue
            where = lowered.split("where", 1)[-1] if "where" in lowered else ""
            # Ownership on its own, with no alternative, is sufficient.
            ownership_only = re.search(r"owner_id\s*=\s*\?\w+", where) and not re.search(
                r"\bor\b", where
            )
            if ownership_only:
                continue
            if re.search(r"\brule\s*>=", where):
                line = text.count("\n", 0, match.start()) + 1
                problems.append(
                    f"{path.relative_to(ROOT)}:{line}: an ab_books query gates access "
                    "on `rule`, which is the book's share ceiling and not a grant. "
                    "Visibility must be ownership or an ab_shares row. "
                    f"Query: {lowered[:160]}"
                )
    return problems


def check_sql_comments_are_quote_free() -> list[str]:
    """A SQL comment line in one of our literals must not contain a quote."""
    problems: list[str] = []
    for path in rust_files():
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            stripped = line.strip()
            if not stripped.startswith("--"):
                continue
            if '"' in stripped:
                problems.append(
                    f"{path.relative_to(ROOT)}:{number}: a SQL comment contains a double "
                    "quote, which closes the enclosing Rust literal. "
                    f"Use a backtick or rephrase: {stripped[:90]}"
                )
    return problems


def main() -> int:
    problems = check_access_predicates() + check_sql_comments_are_quote_free()
    if problems:
        print("source rules violated:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print("source rules OK: address book access is explicit, SQL comments are quote-free")
    return 0


if __name__ == "__main__":
    sys.exit(main())
