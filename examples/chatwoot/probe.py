#!/usr/bin/env python3
"""Run examples/chatwoot/queries.sql through pgmask and pin EXPECT."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from dataclasses import dataclass, field


CANARIES = (
    "alice.cw-canary@inbox.test",
    "+15558675309",
    "555-867-5309",
    "203.0.113.77",
    "CANARYSTRIPE",
    "078-05-4391",
    "CANARYREF",
    "ch_CANARYCHARGE",
    "tok_contact_pubsub_CANARY",
    "CANARYHOOK",
    "cus_CANARYSTRIPE",
)


@dataclass
class Case:
    ident: str
    expect: str
    sql: str
    contains: list[str] = field(default_factory=list)
    refute: list[str] = field(default_factory=list)
    source: str = ""
    notes: str = ""
    search_path: str = ""


def parse_queries(path: str) -> list[Case]:
    text = open(path, encoding="utf-8").read()
    cases: list[Case] = []
    header: dict[str, list[str]] = {}
    sql_lines: list[str] = []
    in_sql = False

    def flush() -> None:
        nonlocal header, sql_lines, in_sql
        sql = "\n".join(sql_lines).strip()
        if not sql:
            header, sql_lines, in_sql = {}, [], False
            return
        ident = header.get("id", ["unnamed"])[0]
        expect = header.get("expect", ["served"])[0]
        cases.append(
            Case(
                ident=ident,
                expect=expect,
                sql=sql,
                contains=header.get("contains", []),
                refute=header.get("refute", []),
                source=(header.get("source") or [""])[0],
                notes=(header.get("notes") or [""])[0],
                search_path=(header.get("search_path") or [""])[0],
            )
        )
        header, sql_lines, in_sql = {}, [], False

    for raw in text.splitlines():
        if raw.startswith("-- @"):
            if in_sql:
                flush()
            key, _, value = raw[4:].partition(":")
            header.setdefault(key.strip(), []).append(value.strip())
            continue
        if raw.startswith("--") or raw.strip() == "":
            continue
        in_sql = True
        sql_lines.append(raw)
        if raw.rstrip().endswith(";"):
            flush()
    flush()
    return cases


def run_psql(
    host: str, port: str, db: str, user: str, sql: str, search_path: str = ""
) -> tuple[int, str]:
    env = os.environ.copy()
    env.setdefault("PGPASSWORD", "")
    if search_path:
        env["PGOPTIONS"] = f"-c search_path={search_path}"
    proc = subprocess.run(
        [
            "psql",
            "-h",
            host,
            "-p",
            port,
            "-U",
            user,
            "-d",
            db,
            "-X",
            "-v",
            "ON_ERROR_STOP=0",
            "-tA",
            "-c",
            sql,
        ],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    out = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, out


def is_refused(output: str) -> bool:
    return "pgmask:" in output.lower()


def classify(output: str, code: int) -> str:
    if is_refused(output):
        return "refused"
    if code != 0 or "ERROR:" in output:
        return "error"
    return "served"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=os.environ.get("PGHOST", "127.0.0.1"))
    parser.add_argument("--port", default=os.environ.get("PGMASK_PORT", "16432"))
    parser.add_argument("--dbname", default=os.environ.get("PGDATABASE", "chatwoot_golden"))
    parser.add_argument("--user", default=os.environ.get("PGUSER", "postgres"))
    parser.add_argument(
        "--queries",
        default=os.path.join(os.path.dirname(__file__), "queries.sql"),
    )
    args = parser.parse_args()

    cases = parse_queries(args.queries)
    if not cases:
        print("no cases parsed", file=sys.stderr)
        return 1

    passed = 0
    failed = 0
    served = 0
    refused = 0
    rows = []

    print(f"{'id':<36} {'expect':<8} {'got':<8} result")
    print("-" * 88)

    for case in cases:
        code, output = run_psql(
            args.host,
            args.port,
            args.dbname,
            args.user,
            case.sql,
            search_path=case.search_path,
        )
        got = classify(output, code)
        if got == "served":
            served += 1
        elif got == "refused":
            refused += 1

        problems: list[str] = []
        if got != case.expect:
            problems.append(f"expected {case.expect}, got {got}")
        for token in CANARIES:
            if token in output:
                problems.append(f"canary leaked: {token}")
        if got == "served":
            for needle in case.contains:
                if needle not in output:
                    problems.append(f"missing {needle!r}")
            for needle in case.refute:
                if needle in output:
                    problems.append(f"must not contain {needle!r}")
        elif case.expect in {"refused", "error"}:
            for needle in case.contains:
                if needle not in output:
                    problems.append(f"missing {needle!r}")

        ok = not problems
        if ok:
            passed += 1
            mark = "PASS"
        else:
            failed += 1
            mark = "FAIL"
        snippet = " ".join(output.split())[:90]
        print(f"{case.ident:<36} {case.expect:<8} {got:<8} {mark}  {snippet}")
        if problems:
            for p in problems:
                print(f"    {p}")
        rows.append((case, got, ok, output))

    print("-" * 88)
    print(
        f"passed {passed}, failed {failed}; served {served}, refused {refused} "
        f"of {len(cases)}"
    )
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
