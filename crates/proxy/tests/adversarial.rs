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
    // One row at a time: the second Execute resumes a suspended portal and
    // arrives with no fresh RowDescription.
    client.send(execute_msg("p1", 1)).await?;
    client.send(sync_msg()).await?;
    client.read_until_ready().await?;
    client.send(execute_msg("p1", 1)).await?;
    client.send(sync_msg()).await?;
    client.read_until_ready_or_eof().await?;
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
    client.read_until_ready_or_eof().await?;
    assert_no_canary(&client, "pipelined interleaved portals");
    Ok(())
}

// --- Bypass: rows arriving detached from their statement --------------------

#[tokio::test]
async fn cursors_stay_masked() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;
    client.simple_query("BEGIN").await?;
    client
        .simple_query("DECLARE c CURSOR FOR SELECT email, name, note FROM canary.subjects")
        .await?;
    client.simple_query("FETCH ALL FROM c").await?;
    client.simple_query("COMMIT").await?;
    assert_no_canary(&client, "cursor FETCH");
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
    client
        .simple_query(
            "SELECT city FROM canary.subjects; \
             SELECT email FROM canary.subjects; \
             SELECT note FROM canary.subjects",
        )
        .await?;
    assert_no_canary(&client, "multi-statement simple query");
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
    client
        .simple_query("SELECT email, name FROM subjects")
        .await?;
    assert_no_canary(&client, "unqualified name after SET search_path");
    Ok(())
}

#[tokio::test]
async fn views_are_masked_through_their_own_oid() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;
    client
        .simple_query("SELECT * FROM canary.subject_view")
        .await?;
    assert_no_canary(&client, "view");
    Ok(())
}

#[tokio::test]
async fn error_detail_cannot_leak() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;
    // A unique violation echoes the conflicting value in DETAIL.
    client
        .simple_query(
            "INSERT INTO canary.subjects VALUES \
             (1, 'CANARY_EMAIL_a1b2c3', 'CANARY_NAME_d4e5f6', 'CANARY_NOTE_97h8i9', 'x')",
        )
        .await?;
    assert!(
        client.received_text().contains("duplicate key"),
        "the useful part of the error should survive"
    );
    assert_no_canary(&client, "error DETAIL");
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
        "DECLARE c2 CURSOR FOR SELECT * FROM canary.subjects",
        "FETCH ALL FROM c2",
        "COMMIT",
        "CREATE TEMP TABLE t2 AS SELECT * FROM canary.subjects",
        "SELECT * FROM t2",
        "SELECT note FROM canary.subjects",
    ] {
        // Some of these hang the connection up by design; reconnect and continue.
        if client.simple_query(sql).await.is_err() {
            assert_no_canary(&client, sql);
            client = RawClient::connect(proxy.addr, DB).await?;
            continue;
        }
        assert_no_canary(&client, sql);
    }

    assert_no_canary(&client, "full sweep");
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
        "SELECT count(email) FROM canary.subjects",
        "SELECT string_agg(email, ',') FROM canary.subjects",
        "SELECT array_agg(email) FROM canary.subjects",
        "SELECT count(*) FILTER (WHERE email = 'CANARY_EMAIL_a1b2c3') FROM canary.subjects",
        "SELECT row_number() OVER (ORDER BY email) FROM canary.subjects",
        "SELECT (SELECT email FROM canary.subjects LIMIT 1)",
        "SELECT coalesce(email, '') FROM canary.subjects",
        "SELECT 1, email FROM canary.subjects",
        "SELECT 1 UNION ALL SELECT 1",
    ] {
        client.simple_query(sql).await?;
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
        client.simple_query(sql).await?;
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
