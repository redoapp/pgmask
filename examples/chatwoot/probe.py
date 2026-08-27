#!/usr/bin/env python3
"""Run examples/chatwoot/queries.sql through pgmask and pin EXPECT."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from dataclasses import dataclass, field


FORBIDDEN_SOURCE_VALUES = (
    "Alice Canary",
    "alice.cw-canary@inbox.test",
    "legacy.cw-canary@inbox.test",
    "Jordan Agent",
    "jordan.agent@acme.example",
    "+15558675309",
    "555-867-5309",
    "widget-alice-1",
    "conv-CANARYIDENTIFIER",
    "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "ORD-9911",
    "203.0.113.77",
    "203.0.113.88",
    "078-05-4391",
    "VIP — billing dispute",
    "alice_canary",
    "alice-canary",
    "MacIntel",
    "CANARYREF",
    "ch_CANARYCHARGE",
    "tok_agent_pubsub",
    "tok_contact_pubsub_CANARY",
    "widget-src-alice",
    "cw-canary-msgid@inbox.test",
    "thread-CANARY@inbox.test",
    "ops@acme.example",
    "msg-CANARYSOURCE",
    "slack-CANARYEXTERNAL",
    "CANARYHOOK",
    "cus_CANARYSTRIPE",
    "draft about Alice",
    "Thanks Alice",
    "missing parcel",
    "Track package",
    "When company is Canary Logistics, add billing label",
    "tier-CANARYPRIVATE",
)

DIRECT_CONTROL_SQL = """
SELECT row_to_json(control)::text
FROM (
  SELECT
    (SELECT json_agg(a) FROM chatwoot.accounts a) AS accounts,
    (SELECT json_agg(u) FROM chatwoot.users u) AS users,
    (SELECT json_agg(c) FROM chatwoot.contacts c) AS contacts,
    (SELECT json_agg(c) FROM chatwoot.conversations c) AS conversations,
    (SELECT json_agg(ci) FROM chatwoot.contact_inboxes ci) AS contact_inboxes,
    (SELECT json_agg(m) FROM chatwoot.messages m) AS messages,
    (SELECT json_agg(r) FROM chatwoot.automation_rules r) AS automation_rules,
    (SELECT json_agg(w) FROM chatwoot.webhooks w) AS webhooks,
    (SELECT json_agg(d) FROM chatwoot.custom_attribute_definitions d)
      AS custom_attribute_definitions,
    (SELECT json_agg(t) FROM chatwoot.tags t) AS tags,
    (SELECT json_agg(tg) FROM chatwoot.taggings tg) AS taggings
) control
"""


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
    direct_expect: str = ""
    direct_contains: list[str] = field(default_factory=list)


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
                direct_expect=(header.get("direct_expect") or [""])[0],
                direct_contains=header.get("direct_contains", []),
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
            "-P",
            "null=[NULL]",
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


def run_psql_script(
    host: str, port: str, db: str, user: str, script: str
) -> tuple[int, str]:
    env = os.environ.copy()
    env.setdefault("PGPASSWORD", "")
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
            "-P",
            "null=[NULL]",
        ],
        check=False,
        capture_output=True,
        text=True,
        input=script,
        env=env,
    )
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def is_refused(output: str) -> bool:
    return "pgmask:" in output.lower()


def classify(output: str, code: int) -> str:
    if is_refused(output):
        return "refused"
    if code != 0 or "ERROR:" in output:
        return "error"
    return "served"

def assert_direct_controls(host: str, port: str, db: str, user: str) -> bool:
    code, output = run_psql(host, port, db, user, DIRECT_CONTROL_SQL)
    if code != 0:
        print(f"FAIL: direct canary control query failed: {' '.join(output.split())}")
        return False
    missing = [token for token in FORBIDDEN_SOURCE_VALUES if token not in output]
    if missing:
        print("FAIL: direct control cannot observe source values:")
        for token in missing:
            print(f"    {token!r}")
        return False
    print(
        f"direct control: exercised {len(FORBIDDEN_SOURCE_VALUES)} "
        "forbidden source values"
    )
    return True


def run_protocol_checks(host: str, port: str, db: str, user: str) -> bool:
    checks = [
        (
            "extended-bind-json-extract",
            """
SELECT additional_attributes->>'city'
FROM chatwoot.contacts
WHERE id = $1
\\bind 1001
\\g
""",
            ("Austin",),
            (),
        ),
        (
            "session-survives-refusal",
            """
SELECT jsonb_pretty(additional_attributes)
FROM chatwoot.contacts WHERE id = 1001;
SELECT additional_attributes->>'city'
FROM chatwoot.contacts WHERE id = 1001;
""",
            ("pgmask:", "Austin"),
            (),
        ),
        (
            "mid-session-search-path-refusal",
            """
SET search_path TO chatwoot;
SELECT contacts.additional_attributes->>'city' FROM contacts WHERE id = 1001;
SELECT additional_attributes->>'city'
FROM chatwoot.contacts WHERE id = 1001;
""",
            ("pgmask:", "Austin"),
            (),
        ),
    ]
    failed = 0
    for name, script, required, forbidden in checks:
        _code, output = run_psql_script(host, port, db, user, script)
        folded_output = output.casefold()
        problems = [f"missing {value!r}" for value in required if value not in output]
        problems.extend(
            f"unexpected {value!r}" for value in forbidden if value in output
        )
        problems.extend(
            f"forbidden source value leaked: {value}"
            for value in FORBIDDEN_SOURCE_VALUES
            if value.casefold() in folded_output
        )
        if problems:
            failed += 1
            print(f"protocol {name}: FAIL")
            for problem in problems:
                print(f"    {problem}")
        else:
            print(f"protocol {name}: PASS")
    print(f"protocol checks: {len(checks) - failed}/{len(checks)} passed")
    return failed == 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=os.environ.get("PGHOST", "127.0.0.1"))
    parser.add_argument("--port", default=os.environ.get("PGMASK_PORT", "16432"))
    parser.add_argument(
        "--direct-port", default=os.environ.get("PGMASK_DIRECT_PORT", "")
    )
    parser.add_argument("--dbname", default=os.environ.get("PGDATABASE", "chatwoot_golden"))
    parser.add_argument("--user", default=os.environ.get("PGUSER", "postgres"))
    parser.add_argument(
        "--queries",
        default=os.path.join(os.path.dirname(__file__), "queries.sql"),
    )
    args = parser.parse_args()

    controls_ok = True
    if args.direct_port:
        controls_ok = assert_direct_controls(
            args.host, args.direct_port, args.dbname, args.user
        )
    else:
        print("direct control: skipped (set --direct-port to prove canaries exist)")

    protocols_ok = run_protocol_checks(
        args.host, args.port, args.dbname, args.user
    )

    cases = parse_queries(args.queries)
    if not cases:
        print("no cases parsed", file=sys.stderr)
        return 1

    passed = 0
    failed = 0
    served = 0
    refused = 0
    errors = 0

    print(f"{'id':<36} {'expect':<8} {'got':<8} result")
    print("-" * 88)

    for case in cases:
        direct_problems: list[str] = []
        if args.direct_port and case.direct_expect:
            direct_code, direct_output = run_psql(
                args.host,
                args.direct_port,
                args.dbname,
                args.user,
                case.sql,
                search_path=case.search_path,
            )
            direct_got = classify(direct_output, direct_code)
            if direct_got != case.direct_expect:
                direct_problems.append(
                    f"direct expected {case.direct_expect}, got {direct_got}"
                )
            for needle in case.direct_contains:
                if needle not in direct_output:
                    direct_problems.append(f"direct missing {needle!r}")

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
        else:
            errors += 1

        problems = direct_problems
        if got != case.expect:
            problems.append(f"expected {case.expect}, got {got}")
        folded_output = output.casefold()
        for token in FORBIDDEN_SOURCE_VALUES:
            if token.casefold() in folded_output:
                problems.append(f"forbidden source value leaked: {token}")
        if got == "served":
            if not output.strip():
                problems.append("served query returned no observable row")
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
    print("-" * 88)
    print(
        f"passed {passed}, failed {failed}; served {served}, refused {refused}, "
        f"errors {errors} of {len(cases)}"
    )
    return 0 if failed == 0 and controls_ok and protocols_ok else 1


if __name__ == "__main__":
    sys.exit(main())
