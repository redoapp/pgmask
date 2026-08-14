#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
//! Phase 4 criteria 2 and 3: the canary property test and the adversarial suite.
//!
//! Every test drives the proxy from a raw wire client and asserts that no
//! sentinel byte ever crossed the boundary. Requires a Postgres with `trust`
//! auth; run via `scripts/test-integration.sh`.

mod support;

use anyhow::Result;
use pgmask::catalog::{Opaque, Unclassified};
use support::*;

const DB: &str = "postgres";

// --- Negative control -------------------------------------------------------

/// If this fails, every other test in this file is meaningless.
#[tokio::test]
async fn negative_control_the_harness_can_see_a_leak() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    // No rules, unclassified allowed: nothing is masked, so the canary must show.
    let proxy = start_proxy_with(DB, vec![], Unclassified::Allow, Opaque::Mask).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;
    client
        .simple_query("SELECT email FROM canary.subjects")
        .await?;
    assert_canary_present(&client, CANARY_EMAIL);
    Ok(())
}

// --- The baseline -----------------------------------------------------------

#[tokio::test]
async fn masks_a_plain_select() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;
    let msgs = client
        .simple_query("SELECT id, email, name, note, city FROM canary.subjects")
        .await?;
    assert!(msgs.iter().any(|m| m.tag == b'D'), "expected data rows");
    assert!(
        client.received_text().contains("Portland"),
        "allowed column"
    );
    assert_no_canary(&client, "plain select");
    Ok(())
}

// --- Bypass: paths that emit rows without a RowDescription ------------------

#[tokio::test]
async fn copy_to_stdout_cannot_leak() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    for sql in [
        "COPY canary.subjects TO STDOUT",
        "COPY (SELECT email FROM canary.subjects) TO STDOUT",
        "COPY canary.subjects (email, name) TO STDOUT WITH CSV",
        "COPY canary.subjects TO STDOUT WITH (FORMAT binary)",
    ] {
        let proxy = start_proxy(DB, default_rules()).await?;
        let mut client = RawClient::connect(proxy.addr, DB).await?;
        client.simple_query(sql).await?;
        assert_refused(&client, sql); // COPY is refused by the read-only allowlist
        assert_no_canary(&client, sql);
    }
    Ok(())
}

#[tokio::test]
async fn function_call_message_cannot_leak() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;
    // OID 2284 is arbitrary; the message must be refused before it is forwarded.
    client.send(function_call_msg(2284)).await?;
    client.read_until_ready_or_eof().await?;
    assert!(
        client.received_text().contains("FunctionCall"),
        "expected an explicit refusal"
    );
    assert_no_canary(&client, "FunctionCall");
    Ok(())
}

// --- Bypass: stale or absent plans ------------------------------------------

#[tokio::test]
async fn execute_without_describe_cannot_leak() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;

    // Parse, Bind, Execute — deliberately no Describe, so the backend sends
    // DataRows with no RowDescription and we have no plan to mask them with.
    client
        .send(parse_msg("s1", "SELECT email FROM canary.subjects"))
        .await?;
    client.send(bind_msg("p1", "s1")).await?;
    client.send(execute_msg("p1", 0)).await?;
    client.send(sync_msg()).await?;
    client.read_until_ready_or_eof().await?;
    // No Describe means no plan; the rows arrive with no described result set
    // and are refused rather than served.
    assert_refused(&client, "Execute without Describe");
    assert_no_canary(&client, "Execute without Describe");
    Ok(())
}

#[tokio::test]
async fn rebinding_a_different_statement_cannot_reuse_a_stale_plan() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;

    // Describe a harmless statement so a permissive plan exists...
    client
        .send(parse_msg("safe", "SELECT city FROM canary.subjects"))
        .await?;
    client.send(describe_statement("safe")).await?;
    client.send(sync_msg()).await?;
    client.read_until_ready().await?;

    // ...then bind and execute a DIFFERENT, never-described statement on the
    // same portal name. If the portal kept the old plan, `note` would be
    // forwarded under `city`'s allow rule.
    client
        .send(parse_msg("sneaky", "SELECT note FROM canary.subjects"))
        .await?;
    client.send(bind_msg("p1", "sneaky")).await?;
    client.send(execute_msg("p1", 0)).await?;
    client.send(sync_msg()).await?;
    client.read_until_ready_or_eof().await?;
    // The rebound portal has no described result set, so it is refused.
    assert_refused(&client, "re-Bind with a stale plan");
    assert_no_canary(&client, "re-Bind with a stale plan");
    Ok(())
}

#[tokio::test]
async fn suspended_and_resumed_portals_stay_masked() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;

    client
        .send(parse_msg("s1", "SELECT email, name FROM canary.subjects"))
        .await?;
    client.send(describe_statement("s1")).await?;
    client.send(bind_msg("p1", "s1")).await?;
    // One row at a time, with NO Sync between the two Executes: a Sync closes
    // the portal, so the earlier version of this test made the second Execute
    // fail on a non-existent portal and never actually resumed anything — the
    // canary check passed on that error. Both Executes then one Sync keeps the
    // portal suspended and resumed, and the second page arrives with no fresh
    // RowDescription — the path that must still be masked.
    client.send(execute_msg("p1", 1)).await?;
    client.send(execute_msg("p1", 1)).await?;
    client.send(sync_msg()).await?;
    let msgs = client.read_until_ready_or_eof().await?;
    assert_served(&msgs, "both pages of the resumed portal");
    assert_no_canary(&client, "resumed portal");
    Ok(())
}

#[tokio::test]
async fn pipelined_interleaved_portals_stay_masked() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;

    // Everything in one write, responses interleaved: the pending-Describe FIFO
    // is the only thing keeping plans attached to the right result sets.
    let mut buf = Vec::new();
    for msg in [
        parse_msg("a", "SELECT city FROM canary.subjects"),
        parse_msg("b", "SELECT email FROM canary.subjects"),
        describe_statement("a"),
        describe_statement("b"),
        bind_msg("pa", "a"),
        bind_msg("pb", "b"),
        execute_msg("pa", 0),
        execute_msg("pb", 0),
        sync_msg(),
    ] {
        buf.extend_from_slice(&msg.encode());
    }
    client.send_raw(&buf).await?;
    let msgs = client.read_until_ready_or_eof().await?;
    assert_served(&msgs, "pipelined interleaved portals");
    assert_no_canary(&client, "pipelined interleaved portals");
    Ok(())
}

// --- Bypass: rows arriving detached from their statement --------------------

#[tokio::test]
async fn sql_declare_and_fetch_are_refused() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;
    client.simple_query("BEGIN").await?;
    client
        .simple_query("DECLARE c CURSOR FOR SELECT email, name, note FROM canary.subjects")
        .await?;
    assert_refused(&client, "DECLARE");
    assert_no_canary(&client, "DECLARE");
    client.simple_query("FETCH ALL FROM c").await?;
    assert_refused(&client, "FETCH");
    assert_no_canary(&client, "FETCH");
    client.simple_query("COMMIT").await?;
    assert_no_canary(&client, "cursor path");
    Ok(())
}

#[tokio::test]
async fn multi_statement_simple_query_stays_masked() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;
    // Several result sets from one Query message, each with its own
    // RowDescription. A plan bound to the request rather than the description
    // would mask the second set with the first set's plan.
    //
    // This assertion used to be `assert_no_canary` alone, which a *refusal*
    // satisfies as readily as correct masking — an error message carries no
    // canary. And a refusal is exactly what happens: pgmask cannot pair the
    // Nth RowDescription with the Nth statement (see
    // analysis::provenance_is_trustworthy, which returns false for anything but
    // a single statement), so it treats every field as opaque and fails closed.
    // The old test passed whether the value was masked, nulled, or the whole
    // query rejected — so it could not have caught a mispairing that served the
    // second set in the clear.
    //
    // Pinned to the real behaviour: fail-closed, and specifically NOT the leak
    // the comment above describes. If multi-statement ever starts being served,
    // the refusal assertion fires and someone must re-check that each set is
    // masked by its own plan before relaxing it.
    client
        .simple_query(
            "SELECT city FROM canary.subjects; \
             SELECT email FROM canary.subjects; \
             SELECT note FROM canary.subjects",
        )
        .await?;
    let text = client.received_text();
    assert_no_canary(&client, "multi-statement simple query");
    assert!(
        text.contains("pgmask:"),
        "multi-statement is fail-closed today; a served result set here is a \
         mispairing that must be proven masked, not assumed:\n{text}"
    );
    // And the leak direction, named explicitly: the released `city` in the
    // first set must not become the plan that serves `email` in the second.
    assert!(
        !text.contains("@"),
        "no address slot may carry a value:\n{text}"
    );
    Ok(())
}

#[tokio::test]
async fn setof_returning_functions_stay_masked() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;
    client
        .simple_query("SELECT * FROM canary.all_subjects()")
        .await?;
    // A user-defined SETOF function is not on the trusted allowlist, so it is
    // refused before it runs — which is why nothing leaks.
    assert_refused(&client, "SETOF function all_subjects()");
    client.simple_query("SELECT * FROM canary.emails()").await?;
    assert_no_canary(&client, "SETOF function");
    Ok(())
}

#[tokio::test]
async fn temp_tables_are_default_denied() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;
    // Temp OIDs are per-session, so the catalog can never contain them. Copying
    // classified data into one must not launder it.
    client
        .simple_query("CREATE TEMP TABLE stash AS SELECT email, name FROM canary.subjects")
        .await?;
    // The read-only allowlist refuses the CREATE, so the laundering table is
    // never even made.
    assert_refused(&client, "CREATE TEMP TABLE");
    client.simple_query("SELECT * FROM stash").await?;
    assert_no_canary(&client, "temp table laundering");
    Ok(())
}

// --- Bypass: expressions and set operations ---------------------------------

#[tokio::test]
async fn expressions_and_set_operations_cannot_leak() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;
    for sql in [
        "SELECT lower(email) FROM canary.subjects",
        "SELECT email || '' FROM canary.subjects",
        "SELECT COALESCE(email, '') FROM canary.subjects",
        "SELECT CASE WHEN id > 0 THEN email END FROM canary.subjects",
        "SELECT string_agg(email, ',') FROM canary.subjects",
        "SELECT email FROM canary.subjects UNION ALL SELECT email FROM canary.subjects",
        "SELECT email FROM canary.subjects INTERSECT SELECT email FROM canary.subjects",
        "WITH RECURSIVE r(e) AS (SELECT email FROM canary.subjects WHERE id = 1 \
         UNION ALL SELECT email FROM canary.subjects WHERE id = 2) SELECT e FROM r",
        "SELECT (SELECT email FROM canary.subjects LIMIT 1)",
        "SELECT to_json(s) FROM canary.subjects s",
        "SELECT row_to_json(s) FROM canary.subjects s",
        "SELECT array_agg(email) FROM canary.subjects",
    ] {
        client.simple_query(sql).await?;
        assert_refused(&client, sql); // every one is an expression/set-op: opaque, refused
        assert_no_canary(&client, sql);
    }
    Ok(())
}

// --- Bypass: session state --------------------------------------------------

#[tokio::test]
async fn search_path_changes_cannot_launder() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;
    // Reaching the same relation by an unqualified name must classify the same,
    // because the catalog is keyed on OID rather than on anything textual.
    client.simple_query("SET search_path TO canary").await?;
    let msgs = client
        .simple_query("SELECT email, name FROM subjects")
        .await?;
    assert_served(&msgs, "unqualified name after SET search_path");
    assert_no_canary(&client, "unqualified name after SET search_path");
    Ok(())
}

#[tokio::test]
async fn views_are_masked_through_their_own_oid() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;
    let msgs = client
        .simple_query("SELECT * FROM canary.subject_view")
        .await?;
    assert_served(&msgs, "view");
    assert_no_canary(&client, "view");
    Ok(())
}

#[tokio::test]
async fn error_detail_cannot_leak() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;
    // A unique violation would echo the conflicting value in DETAIL — the leak
    // this test was written for. The read-only allowlist now refuses the INSERT
    // before it reaches the backend, so that error is never produced: the
    // DETAIL vector is closed one layer earlier than error scrubbing. (General
    // error-text withholding, with the SQLSTATE preserved, is exercised by
    // `a_client_chosen_sqlstate_is_replaced_and_an_ordinary_one_is_not` on the
    // read path, which read-only leaves reachable.)
    client
        .simple_query(
            "INSERT INTO canary.subjects VALUES \
             (1, 'CANARY_EMAIL_a1b2c3', 'CANARY_NAME_d4e5f6', 'CANARY_NOTE_97h8i9', 'x')",
        )
        .await?;
    let text = client.received_text();
    assert!(
        text.contains("read-only"),
        "the write must be refused before it can echo a row:\n{text}"
    );
    assert!(
        !text.contains("duplicate key"),
        "no backend DETAIL exists when the write never runs:\n{text}"
    );
    assert_no_canary(&client, "error DETAIL (write refused)");
    Ok(())
}

// --- A rejection must not poison the session --------------------------------

#[tokio::test]
async fn a_rejection_does_not_break_the_session() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;
    client
        .simple_query("SELECT lower(email) FROM canary.subjects")
        .await?;
    let after = client
        .simple_query("SELECT city FROM canary.subjects")
        .await?;
    assert!(
        after.iter().any(|m| m.tag == b'D'),
        "session should keep serving after a rejection"
    );
    assert_no_canary(&client, "post-rejection recovery");
    Ok(())
}

// --- Everything at once -----------------------------------------------------

/// The property test proper: one session, every path, one assertion.
#[tokio::test]
async fn no_canary_escapes_across_every_path() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;

    for sql in [
        "SELECT * FROM canary.subjects",
        "SELECT * FROM canary.subject_view",
        "SELECT email FROM canary.subjects ORDER BY email DESC",
        "SELECT DISTINCT email FROM canary.subjects",
        "SELECT s.email, t.name FROM canary.subjects s JOIN canary.subjects t USING (id)",
        "WITH c AS (SELECT email FROM canary.subjects) SELECT email FROM c",
        "SELECT email FROM (SELECT email FROM canary.subjects OFFSET 0) q",
        "SELECT * FROM canary.subjects, LATERAL (SELECT 1) x",
        "COPY canary.subjects TO STDOUT",
        "SELECT lower(email) FROM canary.subjects",
        "SELECT email FROM canary.subjects UNION SELECT email FROM canary.subjects",
        "SELECT * FROM canary.all_subjects()",
        "BEGIN",
        // SQL DECLARE/FETCH are refused (sql_prepare_cursor). Still must not
        // leak; reconnect and continue.
        "DECLARE c2 CURSOR FOR SELECT * FROM canary.subjects",
        "FETCH ALL FROM c2",
        "COMMIT",
        "CREATE TEMP TABLE t2 AS SELECT * FROM canary.subjects",
        "SELECT * FROM t2",
        "SELECT note FROM canary.subjects",
    ] {
        // Some of these hang the connection up by design; reconnect and continue.
        match client.simple_query(sql).await {
            Ok(msgs) => {
                assert_exercised(&msgs, &client, sql);
                assert_no_canary(&client, sql);
            }
            Err(_) => {
                // Errored or hung up: the refusal is what closed the path.
                assert_refused(&client, sql);
                assert_no_canary(&client, sql);
                client = RawClient::connect(proxy.addr, DB).await?;
            }
        }
    }

    assert_no_canary(&client, "full sweep");
    Ok(())
}

/// Partitions, inherited children, domain-typed columns and generated columns.
///
/// Each one breaks a different assumption the plan binding makes, and none of
/// them had a fixture — the gap was recorded in `docs/safety-assessment.md` and
/// probed once by hand rather than pinned. Whatever the proxy decides to do
/// with them, the canary must not come out.
///
/// The catalog classifies the parent relations only, which is what an operator
/// would write, and leaves the generated column unclassified. What each query
/// actually does — mask, refuse, or serve — is recorded by the assertions in
/// `relations_that_are_not_plain_tables_behave_as_documented`; this one only
/// insists nothing escapes.
#[tokio::test]
async fn relations_that_are_not_plain_tables_stay_masked() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;

    for sql in [
        // Partitioned: through the parent, and through the partition directly.
        "SELECT * FROM canary.events",
        "SELECT email FROM canary.events",
        "SELECT * FROM canary.events_2024",
        "SELECT email FROM canary.events_2024",
        // Inheritance: parent (which includes children), child alone, and
        // ONLY the parent.
        "SELECT * FROM canary.people",
        "SELECT email FROM canary.people",
        "SELECT * FROM canary.staff",
        "SELECT email FROM canary.staff",
        "SELECT email FROM ONLY canary.people",
        // A domain-typed column, and the same column cast back to text.
        "SELECT * FROM canary.contacts",
        "SELECT email FROM canary.contacts",
        "SELECT email::text FROM canary.contacts",
        // A generated column: the value again, under another name.
        "SELECT * FROM canary.derived",
        "SELECT email_copy FROM canary.derived",
        "SELECT email, email_copy FROM canary.derived",
    ] {
        match client.simple_query(sql).await {
            Ok(msgs) => {
                assert_exercised(&msgs, &client, sql);
                assert_no_canary(&client, sql);
            }
            Err(_) => {
                // Errored or hung up: the refusal is what closed the path.
                assert_refused(&client, sql);
                assert_no_canary(&client, sql);
                client = RawClient::connect(proxy.addr, DB).await?;
            }
        }
    }

    assert_no_canary(&client, "non-plain-table sweep");
    Ok(())
}

/// What each of those four constructs actually does, rather than what I assumed.
///
/// Written after watching them, and two guesses were wrong:
///
/// * A **domain** column masks normally. Postgres reports the *base* type OID
///   in `RowDescription`, not the domain's, so the masker never sees the
///   domain at all. I had expected `is_text_family` to reject an OID allocated
///   at `CREATE DOMAIN` time and refuse the result set.
/// * A read through a **partitioned parent** is masked by the parent's rule.
///   Reading the partition directly falls to default-deny, because the catalog
///   has nothing under that name — safe, and the utility cost an operator will
///   notice and can fix.
///
/// Inheritance behaves the same way as partitioning in both directions,
/// including the child's row coming back through the parent, masked. A cast off
/// a domain column is refused for losing provenance, which is the general rule
/// and not special to domains.
///
/// This exists so the sweep above cannot pass by refusing everything: a
/// refusal and a masked row are both canary-free, and only this distinguishes
/// them.
#[tokio::test]
async fn relations_that_are_not_plain_tables_behave_as_documented() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;

    #[derive(Debug, PartialEq)]
    enum Outcome {
        Served,
        Refused,
    }

    for (sql, want) in [
        // Classified through the parent: served, masked.
        ("SELECT * FROM canary.events", Outcome::Served),
        ("SELECT email FROM canary.events", Outcome::Served),
        // The partition by name is not in the catalog. Default-deny still
        // serves the row; the classified column comes back masked.
        ("SELECT email FROM canary.events_2024", Outcome::Served),
        // Inheritance, including the child's row through the parent.
        ("SELECT email FROM canary.people", Outcome::Served),
        ("SELECT email FROM ONLY canary.people", Outcome::Served),
        ("SELECT email FROM canary.staff", Outcome::Served),
        // A domain-typed column: masked like any other text column.
        ("SELECT email FROM canary.contacts", Outcome::Served),
        // A cast loses provenance, and that is refused — the general rule.
        ("SELECT email::text FROM canary.contacts", Outcome::Refused),
        // A generated column is a second copy of a classified value under an
        // unclassified name. Default-deny is the only thing covering it.
        ("SELECT email_copy FROM canary.derived", Outcome::Served),
        (
            "SELECT email, email_copy FROM canary.derived",
            Outcome::Served,
        ),
    ] {
        let before = client.received_text().len();
        client.simple_query(sql).await?;
        let text = client.received_text();
        let reply = text.get(before..).unwrap_or_default();
        let got = if reply.contains("pgmask:") {
            Outcome::Refused
        } else {
            Outcome::Served
        };
        assert_eq!(got, want, "{sql}\n{reply}");
        assert_no_canary(&client, sql);
        if got == Outcome::Refused {
            client = RawClient::connect(proxy.addr, DB).await?;
        }
    }
    Ok(())
}

/// `RAISE EXCEPTION` lets SQL choose an error's primary message, exactly as
/// `RAISE NOTICE` does for a notice.
///
/// The notice case was found and fixed: `scrub_notice` replaces the `M` field
/// outright, because "the client chooses it outright". `scrub_error` keeps `M`,
/// justified by a comment saying Postgres "composes error messages from its own
/// text rather than from a row" — and `examples/demo/verify.sh` checks the
/// notice path in both directions while checking only that an ordinary backend
/// error survives.
///
/// `RAISE EXCEPTION '%', (SELECT email …)` is the same channel through the
/// other message type. This asserts it is closed.
#[tokio::test]
async fn an_error_message_chosen_by_sql_cannot_carry_a_value() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;

    for sql in [
        // The message, straight out of a subquery.
        "DO $$ BEGIN RAISE EXCEPTION '%', (SELECT email FROM canary.subjects LIMIT 1); END $$;",
        // The same through the fields RAISE also accepts expressions for.
        "DO $$ BEGIN RAISE EXCEPTION 'boom' USING DETAIL = \
         (SELECT email FROM canary.subjects LIMIT 1); END $$;",
        "DO $$ BEGIN RAISE EXCEPTION 'boom' USING HINT = \
         (SELECT email FROM canary.subjects LIMIT 1); END $$;",
        // A value reaching the CONTEXT field by way of a dynamic statement.
        // `CONTEXT: SQL statement "SELECT 1/0 -- alice@example.com"`.
        "DO $$ DECLARE v text; BEGIN \
           SELECT email INTO v FROM canary.subjects LIMIT 1; \
           EXECUTE 'SELECT 1/0 -- ' || v; END $$;",
        // The fields RAISE also accepts expressions for, which were already
        // covered — kept so a change to LEAKY_FIELDS shows up here.
        "DO $$ BEGIN RAISE EXCEPTION 'boom' USING COLUMN = \
         (SELECT email FROM canary.subjects LIMIT 1); END $$;",
        // A unique violation, the channel LEAKY_FIELDS was written for.
        "INSERT INTO canary.subjects VALUES \
         (1, (SELECT email FROM canary.subjects LIMIT 1), 'x', 'y', 'z')",
        // Five characters at a time through a client-chosen SQLSTATE.
        "DO $$ BEGIN RAISE EXCEPTION 'x' USING ERRCODE = \
         upper(substr((SELECT email FROM canary.subjects LIMIT 1), 1, 5)); END $$;",
    ] {
        let before = client.received_text().len();
        let failed = client.simple_query(sql).await.is_err();
        let text = client.received_text();
        let reply = text.get(before..).unwrap_or_default().to_owned();
        // Five characters of a value is the value, only slower. `assert_no_canary`
        // looks for the whole token and would have called the SQLSTATE channel
        // clean.
        assert!(
            !reply.contains("CANAR"),
            "a prefix of the canary crossed the boundary via {sql}:\n{reply}"
        );
        // Every one of these is a DO block or an INSERT that constructs the
        // leaking error, and the read-only allowlist refuses them before the
        // backend runs them. Pin that refusal, or a value that stopped being
        // refused-and-started-carrying would pass the prefix check on a reply
        // that never contained the error at all.
        assert!(
            reply.contains("pgmask:"),
            "the leaking statement must be refused, not silently accepted:\n{reply}"
        );
        assert_no_canary(&client, sql);
        if failed {
            client = RawClient::connect(proxy.addr, DB).await?;
        }
    }
    Ok(())
}

/// An ordinary error keeps its SQLSTATE; one raised from SQL does not.
///
/// The whole justification for withholding the message is that the code
/// survives. It only survives where the client did not choose it.
#[tokio::test]
async fn a_client_chosen_sqlstate_is_replaced_and_an_ordinary_one_is_not() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;

    // No CONTEXT: Postgres chose this code, so it is forwarded.
    client
        .simple_query("SELECT * FROM canary.nonexistent")
        .await?;
    assert!(
        client.received_text().contains("42P01"),
        "an ordinary error must keep its SQLSTATE"
    );

    // Choosing a SQLSTATE takes a `DO` block or a user function, and the
    // read-only allowlist now refuses both before the backend runs them — a
    // stronger close than replacing the code after the fact. The chosen
    // `ZZZZZ` never reaches Postgres at all; the refusal is pgmask's own
    // 42501. (The replace-CONTEXT-bearing-codes logic remains as defence in
    // depth for any error that reaches this path another way.)
    let mut client = RawClient::connect(proxy.addr, DB).await?;
    client
        .simple_query("DO $$ BEGIN RAISE EXCEPTION 'x' USING ERRCODE = 'ZZZZZ'; END $$;")
        .await?;
    let text = client.received_text();
    assert!(
        !text.contains("ZZZZZ"),
        "a chosen SQLSTATE must not pass:\n{text}"
    );
    assert!(
        text.contains("read-only"),
        "a DO block that chooses a SQLSTATE is refused before Postgres runs it:\n{text}"
    );
    Ok(())
}

/// A notice's SQLSTATE is the client's too, and it is the cheaper channel.
///
/// `RAISE NOTICE … USING ERRCODE` takes an expression just as `RAISE EXCEPTION`
/// does. The first cut of the error fix wrote `!notice && …` and left this
/// open. A notice does not abort the transaction, so a loop emits as many as it
/// likes and five characters each carries the whole value in one statement.
#[tokio::test]
async fn a_notice_cannot_smuggle_a_value_through_its_sqlstate() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;

    for level in ["NOTICE", "WARNING", "INFO"] {
        let sql = format!(
            "DO $$ BEGIN RAISE {level} 'x' USING ERRCODE = \
             upper(substr((SELECT email FROM canary.subjects LIMIT 1), 1, 5)); END $$;"
        );
        let before = client.received_text().len();
        let _ = client.simple_query(&sql).await;
        let text = client.received_text();
        let reply = text.get(before..).unwrap_or_default();
        assert!(
            !reply.contains("CANAR"),
            "{level} carried five characters of the value:\n{reply}"
        );
        assert_refused(&client, &sql); // the DO block is refused by the read-only allowlist
        assert_no_canary(&client, &sql);
        client = RawClient::connect(proxy.addr, DB).await?;
    }
    Ok(())
}

/// A reportable GUC must not be able to carry a value.
///
/// `ParameterStatus` is governed by an allowlist of GUC names, and every entry
/// was checked for whether a client can set it. None was checked for *what it
/// accepts*. `scram_iterations` takes an arbitrary integer over a 31-bit range,
/// so it carried any integer-valued masked column verbatim — measured, `987001`
/// derived from a masked column arrived through the proxy.
///
/// The control matters as much as the attack here. The first version of this
/// probe used `SELECT set_config(...)`, which the proxy refuses outright for
/// having no provenance, so every case came back clean and none of them had
/// run.
#[tokio::test]
async fn a_reportable_guc_cannot_carry_a_value() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;

    // Control: a reportable GUC set by a plain `SET` — which read-only allows —
    // must arrive as ParameterStatus, or the injection cases below prove
    // nothing. The old control used `set_config` inside a `DO` block, which the
    // read-only allowlist now refuses, so it could no longer demonstrate that
    // the channel is real.
    client
        .simple_query("SET TimeZone = 'Australia/Eucla'")
        .await?;
    assert!(
        client.received_text().contains("Australia/Eucla"),
        "the reportable-GUC channel is real, or nothing below is being tested"
    );

    // Injecting a masked value needs `set_config` (a function) in a `DO` block —
    // both refused by read-only — or a `SET` whose value is a subquery, which
    // `SET` does not accept. Every route is closed before the backend runs it.
    for (guc, expr) in [
        (
            "scram_iterations",
            "(SELECT 987000 + id FROM canary.subjects LIMIT 1)::text",
        ),
        (
            "application_name",
            "(SELECT email FROM canary.subjects LIMIT 1)",
        ),
        ("search_path", "(SELECT email FROM canary.subjects LIMIT 1)"),
    ] {
        let mut client = RawClient::connect(proxy.addr, DB).await?;
        let sql = format!("DO $$ BEGIN PERFORM set_config('{guc}', {expr}, false); END $$;");
        let _ = client.simple_query(&sql).await;
        let text = client.received_text();
        assert!(
            text.contains("read-only"),
            "GUC injection through a DO block is refused before the backend:\n{text}"
        );
        assert!(
            !text.contains("987001"),
            "{guc} carried a value derived from a masked column:\n{text}"
        );
        assert_no_canary(&client, &sql);
    }
    Ok(())
}

/// Uniqueness the catalog loader could not see, released one row at a time.
///
/// The singleton-group guard refuses `sum(x) GROUP BY <unique key>` because
/// one row per group makes the sum the value. It reads declared unique keys
/// from `pg_index`, and two shapes were invisible to it — both measured
/// returning the exact value `987654321` through the proxy:
///
/// * `UNIQUE (lower(label))` — `indkey` holds 0 for an expression and the
///   inner join to `pg_attribute` dropped the whole index. `lower(label)`
///   unique implies `label` unique, so `GROUP BY label` is provably one row per
///   group from the catalog alone.
/// * `UNIQUE (label) WHERE label IS NOT NULL` — partial indexes were excluded
///   as "only unique over the rows matching their predicate", which is true and
///   is an argument for the opposite conclusion: leaving a key out is the
///   releasing direction.
///
/// `sum`, not `max`: `max` can return a stored value whatever the grouping, so
/// it is refused unconditionally and a test built on it measures nothing. The
/// first version of this used `max` and every case came back refused.
#[tokio::test]
async fn a_unique_key_the_loader_cannot_see_still_refuses() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;

    // The control comes first and is the reason the rest means anything: a
    // grouping with no unique key behind it must be *served*, or "refused" is
    // just the proxy refusing everything.
    //
    // `bucketname`, not `label`: unique keys are held unscoped, so a key on any
    // relation refuses a grouping by that name everywhere.
    let mut client = RawClient::connect(proxy.addr, DB).await?;
    client
        .simple_query("SELECT bucketname, sum(salary) FROM canary.no_unique GROUP BY bucketname")
        .await?;
    let text = client.received_text();
    assert!(
        !text.contains("pgmask:"),
        "a genuine aggregate must still be served, or this test proves nothing:\n{text}"
    );

    for (what, sql) in [
        (
            "an expression unique index, grouped by the expression",
            "SELECT lower(exprkey), sum(salary) FROM canary.expr_unique GROUP BY lower(exprkey)",
        ),
        (
            "an expression unique index, grouped by the bare column",
            "SELECT exprkey, sum(salary) FROM canary.expr_unique GROUP BY exprkey",
        ),
        (
            "a partial unique index, query matching the predicate",
            "SELECT label, sum(salary) FROM canary.partial_unique \
          WHERE label IS NOT NULL GROUP BY label",
        ),
        (
            "a partial unique index, no predicate",
            "SELECT label, sum(salary) FROM canary.partial_unique GROUP BY label",
        ),
        // The ordinary case, and the one the first attempt at this fix
        // destroyed: a constraint-backed index records its columns only through
        // `pg_constraint`, so a loader reading `pg_depend` alone sees nothing
        // here and the guard stops firing on almost every real table.
        (
            "a PRIMARY KEY",
            "SELECT pkid, sum(salary) FROM canary.pk_unique GROUP BY pkid",
        ),
        (
            "a UNIQUE constraint",
            "SELECT ucid, sum(salary) FROM canary.uc_unique GROUP BY ucid",
        ),
    ] {
        let mut client = RawClient::connect(proxy.addr, DB).await?;
        let _ = client.simple_query(sql).await;
        let text = client.received_text();
        assert!(
            !text.contains("987654321"),
            "{what} disclosed the exact value:\n{text}"
        );
        assert!(
            text.contains("pgmask:"),
            "{what} should have been refused, not merely masked:\n{text}"
        );
    }
    Ok(())
}

/// `SET ROLE` cannot reach a looser mask, because pgmask's roles are not the
/// database's.
///
/// `[[role]]` maps a *startup principal* to pgmask role names, resolved once at
/// `AuthenticationOk` and never again. A reader who assumes it follows `SET
/// ROLE` would configure this wrongly in the dangerous direction, and nothing
/// said otherwise: before this test, no test, script or document in the
/// repository mentioned `SET ROLE` at all.
///
/// The fixture is the shape that would actually matter: a role whose `by_role`
/// mask *releases* the column, and a principal who is not a member of it.
#[tokio::test]
async fn set_role_cannot_reach_another_roles_mask() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;

    let mut rules = default_rules();
    for r in &mut rules {
        if r.relation == "canary.subjects" && r.column == "email" {
            // `analyst` sees it in the clear. The connecting principal is
            // `postgres`, and no `[[role]]` declares postgres a member.
            r.by_role.insert("analyst".into(), pgmask::mask::Mask::None);
        }
    }
    let proxy = start_proxy(DB, rules).await?;

    // Control: the looser mask exists and is reachable by someone. If this
    // stops being true the assertions below pass for the wrong reason.
    let with_role = start_proxy_as_member(DB, "analyst").await?;
    let mut member = RawClient::connect(with_role.addr, DB).await?;
    member
        .simple_query("SELECT email FROM canary.subjects LIMIT 1")
        .await?;
    assert!(
        member.received_text().contains(CANARY_EMAIL),
        "the `analyst` mask must actually release, or this test asserts nothing"
    );

    for attempt in [
        "SET ROLE postgres",
        "SET ROLE analyst",
        "SET SESSION AUTHORIZATION postgres",
        "SET LOCAL ROLE postgres",
    ] {
        let mut client = RawClient::connect(proxy.addr, DB).await?;
        let _ = client.simple_query(attempt).await;
        let _ = client
            .simple_query("SELECT email FROM canary.subjects LIMIT 1")
            .await;
        assert_no_canary(&client, attempt);
    }
    Ok(())
}

/// A catalog with no column rules at all still masks, and still refuses.
///
/// `resolve_snapshot` takes an early return when `rules.is_empty()`, building a
/// second `Snapshot` from the same parts. No test went down that path — a
/// catalog with no rules classifies nothing, so it looked like it could not
/// matter — and the mutation campaign duly reported every field of that struct
/// as deletable with nothing noticing.
///
/// It does matter. An operator whose catalog failed to load, or who has not
/// written it yet, is exactly the person default-deny is for, and the snapshot
/// on that path still carries the system-relation set and the opaque-view set
/// that decide what is refused.
#[tokio::test]
async fn an_empty_catalog_masks_everything_and_still_refuses() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, Vec::new()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;

    for sql in [
        "SELECT email FROM canary.subjects",
        "SELECT * FROM canary.subjects",
        "SELECT email FROM canary.subject_view",
        // The release paths must stay shut too: with no rules there is no
        // column anyone declared safe.
        "SELECT city, count(*) FROM canary.subjects GROUP BY city",
        "SELECT lower(email) FROM canary.subjects",
    ] {
        match client.simple_query(sql).await {
            Ok(msgs) => {
                assert_exercised(&msgs, &client, sql);
                assert_no_canary(&client, sql);
            }
            Err(_) => {
                // Errored or hung up: the refusal is what closed the path.
                assert_refused(&client, sql);
                assert_no_canary(&client, sql);
                client = RawClient::connect(proxy.addr, DB).await?;
            }
        }
    }
    Ok(())
}

/// An error still says enough to act on.
///
/// Withholding the message is only defensible if the `SQLSTATE` survives — it
/// is the machine-readable half, and every driver surfaces it. If this stops
/// holding, the proxy has become opaque rather than careful.
#[tokio::test]
async fn an_error_still_carries_its_sqlstate() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;

    client
        .simple_query("SELECT * FROM canary.nonexistent")
        .await?;
    let text = client.received_text();
    assert!(
        text.contains("42P01"),
        "the SQLSTATE for undefined_table should survive:\n{text}"
    );
    assert!(
        text.contains("error text withheld by pgmask"),
        "and the message should not:\n{text}"
    );
    // Not the `pgmask:` prefix, which means the proxy refused the statement.
    // This one ran and failed on its own; conflating the two made the generated
    // campaign misclassify 20,034 statements.
    assert!(
        !text.contains("pgmask: "),
        "a backend error must not read as a proxy refusal:\n{text}"
    );
    Ok(())
}

// --- The rescue path --------------------------------------------------------
//
// analysis.rs turns refusals into passthroughs for expressions positively
// identified as carrying no column value. That direction is the dangerous one:
// a wrong rule here is a leak, not a false pass. These tests exist to make sure
// nothing can ride through it.

#[tokio::test]
async fn provably_column_free_expressions_are_served() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;

    for sql in [
        "SELECT 1",
        "SELECT now()",
        "SELECT current_database()",
        "SELECT count(*) FROM canary.subjects",
        "SELECT city, count(*) FROM canary.subjects GROUP BY city",
    ] {
        let msgs = client.simple_query(sql).await?;
        assert!(
            msgs.iter().any(|m| m.tag == b'D'),
            "{sql} should now be served, not refused"
        );
        assert_no_canary(&client, sql);
    }
    Ok(())
}

#[tokio::test]
async fn the_rescue_path_cannot_be_tricked() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;

    // Every one of these is an expression that either emits a stored value or
    // reveals something about one. None may be rescued.
    for sql in [
        "SELECT max(email) FROM canary.subjects",
        "SELECT min(email) FROM canary.subjects",
        "SELECT string_agg(email, ',') FROM canary.subjects",
        "SELECT array_agg(email) FROM canary.subjects",
        "SELECT json_agg(email) FROM canary.subjects",
        "SELECT first_value(email) OVER (ORDER BY id) FROM canary.subjects",
        "SELECT last_value(email) OVER (ORDER BY id) FROM canary.subjects",
        "SELECT lag(email) OVER (ORDER BY id) FROM canary.subjects",
        "SELECT nth_value(email, 1) OVER (ORDER BY id) FROM canary.subjects",
        "SELECT mode() WITHIN GROUP (ORDER BY email) FROM canary.subjects",
        "SELECT (SELECT email FROM canary.subjects LIMIT 1)",
        "SELECT coalesce(email, '') FROM canary.subjects",
        "SELECT 1, email FROM canary.subjects",
        "SELECT 1 UNION ALL SELECT 1",
    ] {
        let msgs = client.simple_query(sql).await?;
        assert_exercised(&msgs, &client, sql); // rescued-and-served or refused, never silent
        assert_no_canary(&client, sql);
    }
    Ok(())
}

/// The position mapping is the subtle part: target-list index i must really be
/// described field i, or a literal could claim a classified column's slot.
#[tokio::test]
async fn a_star_expansion_cannot_shift_a_literal_onto_a_column() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;
    for sql in [
        "SELECT *, 1 FROM canary.subjects",
        "SELECT 1, * FROM canary.subjects",
        "SELECT s.*, count(*) OVER () FROM canary.subjects s",
    ] {
        let msgs = client.simple_query(sql).await?;
        assert_exercised(&msgs, &client, sql); // served-masked or refused, never silent
        assert_no_canary(&client, sql);
    }
    Ok(())
}

/// The extended protocol carries SQL in `Parse`, not in `Query`, so the
/// analysis has to find it by a different route.
#[tokio::test]
async fn the_rescue_path_works_and_holds_over_the_extended_protocol() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;

    // Safe: should come back with rows.
    client
        .send(parse_msg("s1", "SELECT count(*) FROM canary.subjects"))
        .await?;
    client.send(describe_statement("s1")).await?;
    client.send(bind_msg("p1", "s1")).await?;
    client.send(execute_msg("p1", 0)).await?;
    client.send(sync_msg()).await?;
    let msgs = client.read_until_ready().await?;
    assert!(
        msgs.iter().any(|m| m.tag == b'D'),
        "count(*) should be served"
    );

    // Unsafe: must not be rescued just because a safe statement preceded it.
    client
        .send(parse_msg("s2", "SELECT max(email) FROM canary.subjects"))
        .await?;
    client.send(describe_statement("s2")).await?;
    client.send(bind_msg("p2", "s2")).await?;
    client.send(execute_msg("p2", 0)).await?;
    client.send(sync_msg()).await?;
    client.read_until_ready_or_eof().await?;
    assert_no_canary(&client, "extended protocol rescue path");
    Ok(())
}

/// Summaries over classified columns are released now, on the stated bar of
/// "you cannot read an anonymised value". These must come back with rows *and*
/// without a sentinel — the canary assertion is what makes the relaxation safe
/// rather than merely convenient.
#[tokio::test]
async fn summaries_are_served_without_leaking() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;

    for sql in [
        "SELECT count(email) FROM canary.subjects",
        "SELECT count(DISTINCT email) FROM canary.subjects",
        "SELECT city, count(*) FROM canary.subjects GROUP BY city",
        "SELECT count(*) FILTER (WHERE email = 'CANARY_EMAIL_a1b2c3') FROM canary.subjects",
        "SELECT row_number() OVER (ORDER BY email) FROM canary.subjects",
        "SELECT rank() OVER (ORDER BY name) FROM canary.subjects",
    ] {
        let msgs = client.simple_query(sql).await?;
        assert!(msgs.iter().any(|m| m.tag == b'D'), "{sql} should be served");
        assert_no_canary(&client, sql);
    }
    Ok(())
}

/// A masked column stays masked after DDL moves its attnum — the catalog-race
/// guarantee, under the default (deny) posture.
///
/// `ALTER TABLE ... DROP COLUMN secret; ADD COLUMN secret` gives `secret` a new
/// attnum while the table OID is unchanged, so the proxy's snapshot — resolved
/// at startup to the old attnum — no longer recognises the column. Under
/// default-deny a lookup miss masks, so this must show nothing in the clear no
/// matter when the query lands relative to the next refresh.
///
/// Found by hammering a live proxy: under `allow` the same reshape served the
/// column in plaintext for the whole refresh interval, because a known table
/// OID nudged no refresh. Default-deny was and is safe; this pins that, since
/// it is the guarantee the product rests on.
#[tokio::test]
async fn a_reshaped_masked_column_stays_masked_under_default_deny() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    exec_direct(
        DB,
        "DROP TABLE IF EXISTS canary.reshape;
         CREATE TABLE canary.reshape (id int, secret text);
         INSERT INTO canary.reshape VALUES (1, 'CANARY_NOTE_97h8i9')",
    )
    .await?;

    let rules = vec![
        rule("canary.reshape", "id", pgmask::mask::Mask::None),
        rule("canary.reshape", "secret", pgmask::mask::Mask::Redact),
    ];
    let proxy = start_proxy_with(DB, rules, Unclassified::Mask, Opaque::Reject).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;

    let before = client
        .simple_query("SELECT secret FROM canary.reshape")
        .await?;
    assert_served(&before, "reshape: before ALTER"); // masked (NULL), but served
    assert_no_canary(&client, "reshape: before ALTER");

    // Move the attnum out from under the snapshot.
    exec_direct(
        DB,
        "ALTER TABLE canary.reshape DROP COLUMN secret;
         ALTER TABLE canary.reshape ADD COLUMN secret text;
         UPDATE canary.reshape SET secret = 'CANARY_NOTE_97h8i9'",
    )
    .await?;

    // The snapshot still points at the old attnum; the new one is a lookup
    // miss. Default-deny must mask it, with no dependence on refresh timing.
    let mut after = RawClient::connect(proxy.addr, DB).await?;
    let msgs = after
        .simple_query("SELECT secret FROM canary.reshape")
        .await?;
    // Default-deny masks the reshaped column to NULL and still serves the row —
    // the guarantee is that the value never appears, not that the query is
    // refused.
    assert_served(&msgs, "reshape: immediately after ALTER");
    assert_no_canary(&after, "reshape: immediately after ALTER");

    exec_direct(DB, "DROP TABLE IF EXISTS canary.reshape").await?;
    Ok(())
}
