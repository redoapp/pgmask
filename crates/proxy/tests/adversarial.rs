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
    let text = client.received_text();
    // The message used to be asserted here. It is withheld now, because
    // `RAISE EXCEPTION` lets SQL choose one and there is no locale-independent
    // way to tell those apart — see `an_error_message_chosen_by_sql_cannot_
    // carry_a_value`. What has to survive is the SQLSTATE: 23505 is
    // unique_violation, and this error has no CONTEXT, so the code is Postgres'
    // own and is forwarded.
    assert!(
        !text.contains("duplicate key"),
        "the message is SQL-choosable and must not survive:\n{text}"
    );
    assert!(
        text.contains("23505"),
        "but the SQLSTATE must, or the proxy is merely opaque:\n{text}"
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
        if client.simple_query(sql).await.is_err() {
            assert_no_canary(&client, sql);
            client = RawClient::connect(proxy.addr, DB).await?;
            continue;
        }
        assert_no_canary(&client, sql);
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

    // A CONTEXT proves it came through user SQL, so the code is replaced.
    let mut client = RawClient::connect(proxy.addr, DB).await?;
    client
        .simple_query("DO $$ BEGIN RAISE EXCEPTION 'x' USING ERRCODE = 'ZZZZZ'; END $$;")
        .await?;
    let text = client.received_text();
    assert!(
        !text.contains("ZZZZZ"),
        "a chosen SQLSTATE must not pass:\n{text}"
    );
    assert!(text.contains("XX000"), "and it must be replaced:\n{text}");
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
        assert_no_canary(&client, &sql);
        client = RawClient::connect(proxy.addr, DB).await?;
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
