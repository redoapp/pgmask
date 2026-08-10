#!/usr/bin/env python3
"""Break each guard on purpose and check the suite notices.

    ./scripts/test-mutations.py [name-substring]

Every other suite here asks "does the proxy leak?". This one asks a question
none of them can: **would we find out if a fix were undone?**

Every guard below was added after a real disclosure, most found by an audit
rather than by this suite. A guard with no test that fails when it is removed
can be deleted by a future refactor in silence — and this repo has already had
a fix silently reverted by an editor, and a test file rewritten underneath a
patch, in a single day.

For each mutation: apply it, rebuild, run the narrowest suite that ought to
catch it, and require that suite to FAIL. A mutation that SURVIVES is a hole in
the suite, not in the proxy.

A mutation that no longer applies is reported STALE and fails the run: it means
this file has drifted from the source and is quietly testing less than it says.
A mutation that fails to *compile* is reported CAUGHT-BY-COMPILER, which is a
weaker result — the guard cannot be silently deleted, but nothing asserts its
behaviour — so those are listed separately rather than counted as covered.

Python, not bash: the mutation table holds Rust source with `|`, `&&` and
closures in it, and an earlier bash version split fields on `|` straight
through the middle of `|t| t.strip_suffix(...)`, silently turning a
condition-weakening mutation into a delete-the-line one that failed to compile
and looked like a pass.
"""

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# (name, file, old, new, suite that must fail)
# `new = None` deletes the matched text.
MUTATIONS = [
    (
        "set-operation provenance",
        "crates/proxy/src/analysis.rs",
        "select.op() != pg_query::protobuf::SetOperation::SetopNone",
        "false",
        "cargo test -p pgmask -q set_operations_are_never_trusted",
    ),
    (
        "windowed aggregate",
        "crates/proxy/src/analysis.rs",
        "if call.over.is_none() && REDUCING_AGGREGATES.contains(&name)",
        "if REDUCING_AGGREGATES.contains(&name)",
        "cargo test -p pgmask -q a_reducing_aggregate_over_a_window",
    ),
    (
        "value-size functions",
        "crates/proxy/src/analysis.rs",
        '    "pg_size_pretty",\n    "pg_size_bytes",\n    "pg_column_size",\n',
        "",
        "cargo test -p pgmask -q size_functions",
    ),
    (
        "star alignment",
        "crates/proxy/src/analysis.rs",
        "        && !select.target_list.iter().any(target_is_star)",
        "",
        "cargo test -p pgmask -q analysis::",
    ),
    (
        "srf in FROM",
        "crates/proxy/src/analysis.rs",
        "                        if !safe {\n                            return false;\n                        }",
        "",
        "cargo test -p pgmask -q metadata",
    ),
    (
        "lexer sees quoted names",
        "crates/proxy/src/analysis.rs",
        "if let Some(inner) = text.strip_prefix('\"').and_then(|t| t.strip_suffix('\"'))",
        "if let Some(inner) = text.strip_prefix('\\u{1}').and_then(|t| t.strip_suffix('\\u{1}'))",
        "cargo test -p pgmask --test lineage_superset",
    ),
    (
        "lineage masked-column backstop",
        "crates/proxy/src/lineage.rs",
        "None if masked_column_in_statement => Verdict::Unresolved,",
        "",
        "cargo test -p pgmask -q a_masked_column_anywhere_blocks_release",
    ),
    (
        "opaque-view source guard",
        "crates/proxy/src/lineage.rs",
        "if snapshot.relation_is_opaque_view(&relation) {\n                    return Verdict::Unresolved;\n                }",
        "",
        "cargo test -p pgmask -q set_operation_view",
    ),
    (
        "opaque-view statement guard",
        "crates/proxy/src/catalog.rs",
        "            Some(identifiers) => identifiers\n                .iter()\n                .any(|identifier| self.is_opaque_view(None, identifier)),",
        "            Some(_) => false,",
        "cargo test -p pgmask -q opaque_view",
    ),
    (
        "range fails open",
        "crates/proxy/src/mask.rs",
        '    if start >= chars.len() {\n        return "*".repeat(chars.len());\n    }',
        "",
        "cargo test -p pgmask -q string_masks_never_fail_open",
    ),
    (
        "outer fails open",
        "crates/proxy/src/mask.rs",
        '    if keep == 0 {\n        return "*".repeat(chars.len());\n    }',
        "",
        "cargo test -p pgmask -q string_masks_never_fail_open",
    ),
    (
        "duplicate catalog rules",
        "crates/proxy/src/catalog.rs",
        "            if !seen.insert(key) {",
        "            if false && !seen.insert(key) {",
        "cargo test -p pgmask -q catalog::",
    ),
    (
        "plan invalidation on refresh",
        "crates/proxy/src/plan_state.rs",
        "        self.statement_plans.clear();\n        self.portal_plans.clear();",
        "",
        "cargo test -p pgmask -q a_catalog_refresh",
    ),
    (
        "ambiguous principal",
        "crates/proxy/src/session.rs",
        "    if users.next().is_some() {\n        return None;\n    }",
        "",
        "cargo test -p pgmask -q two_users",
    ),
    (
        "singleton-group aggregate",
        "crates/proxy/src/session.rs",
        "let allow_summaries = self.policy.summaries == Summaries::Allow && !singleton_groups;",
        "let allow_summaries = self.policy.summaries == Summaries::Allow;",
        "./scripts/test-inference.sh",
    ),
    (
        "unreadable grouping releases",
        "crates/proxy/src/analysis.rs",
        "            // `GroupingSet`. Reading it would mean matching on the function\n            // name, and `cube` is a real function from a real extension.\n            _ => None,",
        "            // `GroupingSet`. Reading it would mean matching on the function\n            // name, and `cube` is a real function from a real extension.\n            _ => Some(()),",
        "./scripts/test-inference.sh",
    ),
    (
        "ordinal grouping unread",
        "crates/proxy/src/analysis.rs",
        "                walk(\n                    target.val.as_ref()?,\n                    targets,\n                    into,\n                    depth.saturating_add(1),\n                    false,\n                )",
        "                None",
        "./scripts/test-inference.sh",
    ),
    (
        "lexical backstop on an unreadable grouping",
        "crates/proxy/src/session.rs",
        "                None => match inspection.identifiers() {\n                    Some(named) => snapshot.grouping_covers_a_unique_key(named),\n                    // A statement we cannot even lex is one we cannot clear.\n                    None => true,\n                },",
        "                None => false,",
        "./scripts/test-inference.sh",
    ),
    (
        "output-alias resolution",
        "crates/proxy/src/analysis.rs",
        "                if as_element && column.fields.len() == 1 {",
        "                if false && column.fields.len() == 1 {",
        "./scripts/test-inference.sh",
    ),
    (
        "alias resolved inside a grouping set",
        "crates/proxy/src/analysis.rs",
        "                    walk(member, targets, into, depth.saturating_add(1), as_element)?;\n                }\n                Some(())\n            }\n            // A multi-column set inside",
        "                    walk(member, targets, into, depth.saturating_add(1), false)?;\n                }\n                Some(())\n            }\n            // A multi-column set inside",
        "./scripts/test-inference.sh",
    ),
    (
        "notice text withheld",
        "crates/proxy/src/protocol.rs",
        "        if notice && field == b'M' {",
        "        if false && field == b'M' {",
        "env KEEP=0 ./examples/demo/verify.sh",
    ),
    (
        "notification withheld",
        "crates/proxy/src/session.rs",
        "            protocol::B_NOTIFICATION_RESPONSE => {}",
        "            protocol::B_NOTIFICATION_RESPONSE => out.client(Vetted::control(&msg)),",
        "env KEEP=0 ./examples/demo/verify.sh",
    ),
]

GREEN, RED, YELLOW, DIM, OFF = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"


def run(cmd: str) -> int:
    return subprocess.run(
        cmd, shell=True, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    ).returncode


def main() -> int:
    wanted = sys.argv[1] if len(sys.argv) > 1 else ""
    caught, compiler, survived, stale = [], [], [], []

    for name, rel, old, new, suite in MUTATIONS:
        if wanted and wanted not in name:
            continue
        path = ROOT / rel
        original = path.read_text()
        if old not in original:
            stale.append((name, "no longer matches the source"))
            continue

        print(f"==> {name}", flush=True)
        path.write_text(original.replace(old, new or "", 1))
        try:
            if run("cargo build --release -q") != 0:
                compiler.append(name)
            elif run(suite) == 0:
                survived.append((name, suite))
            else:
                caught.append((name, suite))
        finally:
            path.write_text(original)

    run("cargo build --release -q")

    print("\n" + "-" * 68)
    for name, suite in caught:
        print(f"  {name:<32} {GREEN}CAUGHT{OFF}    {DIM}{suite[:44]}{OFF}")
    for name in compiler:
        print(f"  {name:<32} {YELLOW}COMPILER{OFF}  {DIM}no behavioural test, only the type system{OFF}")
    for name, suite in survived:
        print(f"  {name:<32} {RED}SURVIVED{OFF}  {suite[:44]}")
    for name, why in stale:
        print(f"  {name:<32} {YELLOW}STALE{OFF}     {why}")
    print("-" * 68)
    print(
        f"  {len(caught)} caught, {len(compiler)} compiler-only, "
        f"{len(survived)} survived, {len(stale)} stale"
    )
    return 0 if not survived and not stale else 1


if __name__ == "__main__":
    sys.exit(main())
