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

/// Catalog rules for stored `json`/`jsonb` columns, including the view that
/// reports its own OID. Pointer policy is shared so a provenance-preserving
/// rewrite cannot pick a weaker JSON plan than the base table.
fn classified_json_document_rules() -> Vec<pgmask::catalog::ColumnRule> {
    let document_rule = |relation: &str, column: &str| {
        let mut email = json_field("/profile/email", pgmask::mask::Mask::Partial);
        email.params.keep = Some(4);
        json_rule(
            relation,
            column,
            pgmask::mask::JsonUnmatched::TypePlaceholders,
            vec![
                json_field("/profile", pgmask::mask::Mask::None),
                email,
                json_field("/profile/name", pgmask::mask::Mask::Redact),
                json_field("/public", pgmask::mask::Mask::None),
                json_field("/items/*", pgmask::mask::Mask::None),
                json_field("/items/*/token", pgmask::mask::Mask::Redact),
                json_field("/numeric_object/*", pgmask::mask::Mask::None),
                json_field("/numeric_object/*/token", pgmask::mask::Mask::Redact),
                json_field("/a~1b/~0key", pgmask::mask::Mask::Redact),
            ],
        )
    };
    let mut rules = default_rules();
    for relation in ["canary.documents", "canary.documents_view"] {
        // PRIMARY KEY `id` is not sensitive, but it is NOT NULL. Leaving it
        // unclassified makes the type-aware fallback try SQL NULL and refuse
        // `SELECT *`. Catalogue it as released so star expansion is a real
        // JSON-masking path rather than a NOT NULL refusal.
        rules.push(rule(relation, "id", pgmask::mask::Mask::None));
        rules.push(document_rule(relation, "payload"));
        rules.push(document_rule(relation, "legacy"));
    }
    rules.push(json_rule(
        "canary.documents",
        "encoded",
        pgmask::mask::JsonUnmatched::TypePlaceholders,
        Vec::new(),
    ));
    rules
}

#[derive(Debug)]
enum JsonSqlValue {
    Text(&'static str),
    Json(serde_json::Value),
    Null,
}

struct JsonSqlValueCase {
    name: &'static str,
    sql: &'static str,
    direct: JsonSqlValue,
    masked: JsonSqlValue,
    poison: Option<&'static str>,
}

fn assert_single_sql_value(rows: &[Vec<Option<String>>], expected: &JsonSqlValue, context: &str) {
    assert_eq!(rows.len(), 1, "{context}: expected one row, got {rows:?}");
    assert_eq!(
        rows[0].len(),
        1,
        "{context}: expected one field, got {:?}",
        rows[0]
    );
    match expected {
        JsonSqlValue::Text(expected) => {
            assert_eq!(rows[0][0].as_deref(), Some(*expected), "{context}")
        }
        JsonSqlValue::Json(expected) => {
            let actual = rows[0][0]
                .as_ref()
                .unwrap_or_else(|| panic!("{context}: expected JSON, got SQL NULL"));
            let actual: serde_json::Value = serde_json::from_str(actual)
                .unwrap_or_else(|error| panic!("{context}: invalid JSON {actual:?}: {error}"));
            assert_eq!(&actual, expected, "{context}");
        }
        JsonSqlValue::Null => assert_eq!(rows[0][0], None, "{context}"),
    }
}

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

#[tokio::test]
async fn structure_aware_json_masks_arbitrary_nesting_in_text_and_binary_formats() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;

    // Poison controls for both formats: the same rows and clients must expose
    // the canary when the whole JSON column is explicitly released.
    let mut released_rules = default_rules();
    released_rules.push(rule(
        "canary.documents",
        "payload",
        pgmask::mask::Mask::None,
    ));
    released_rules.push(rule("canary.documents", "legacy", pgmask::mask::Mask::None));
    released_rules.push(rule(
        "canary.documents",
        "encoded",
        pgmask::mask::Mask::None,
    ));
    let released = start_proxy(DB, released_rules).await?;
    let mut text_control = RawClient::connect(released.addr, DB).await?;
    text_control
        .simple_query("SELECT payload, legacy, encoded FROM canary.documents")
        .await?;
    assert_canary_present(&text_control, CANARY_EMAIL);

    let mut binary_control = RawClient::connect(released.addr, DB).await?;
    binary_control
        .send(parse_msg(
            "s",
            "SELECT payload FROM canary.documents WHERE id = 1",
        ))
        .await?;
    binary_control.send(describe_statement("s")).await?;
    binary_control
        .send(bind_msg_with_result_format("p", "s", 1))
        .await?;
    binary_control.send(execute_msg("p", 0)).await?;
    binary_control.send(sync_msg()).await?;
    let control_msgs = binary_control.read_until_ready().await?;
    assert_served(&control_msgs, "binary JSON poison control");
    assert_canary_present(&binary_control, CANARY_EMAIL);

    let masked = start_proxy(DB, classified_json_document_rules()).await?;

    let mut text_client = RawClient::connect(masked.addr, DB).await?;
    let text_msgs = text_client
        .simple_query("SELECT payload, legacy, encoded FROM canary.documents")
        .await?;
    assert_served(&text_msgs, "text json and jsonb");
    assert_no_canary(&text_client, "structure-aware JSON text formats");
    let text = text_client.received_text();
    assert!(text.contains(r#""email":"***************b2c3""#), "{text}");
    assert!(text.contains(r#""name":"***""#), "{text}");
    assert!(text.contains(r#""public":"Portland""#), "{text}");
    assert!(text.contains(r#""city":"Denver""#), "{text}");
    assert!(text.contains(r#""city":"Seattle""#), "{text}");
    assert!(text.contains(r#""unknown":"""#), "{text}");
    assert!(text.contains(r#""n":0"#), "{text}");
    assert!(text.contains(r#""enabled":false"#), "{text}");

    let mut binary_client = RawClient::connect(masked.addr, DB).await?;
    binary_client
        .send(parse_msg(
            "s",
            "SELECT payload FROM canary.documents WHERE id = 1",
        ))
        .await?;
    binary_client.send(describe_statement("s")).await?;
    binary_client
        .send(bind_msg_with_result_format("p", "s", 1))
        .await?;
    binary_client.send(execute_msg("p", 0)).await?;
    binary_client.send(sync_msg()).await?;
    let binary_msgs = binary_client.read_until_ready().await?;
    assert_served(&binary_msgs, "binary jsonb");
    assert_no_canary(&binary_client, "structure-aware binary jsonb");
    let binary = binary_client.received_text();
    assert!(binary.contains(r#""public":"Portland""#), "{binary}");
    assert!(binary.contains(r#""city":"Denver""#), "{binary}");

    // `json` binary is UTF-8 JSON text with no version byte. The jsonb path
    // above must not be the only format the live server exercises.
    let mut json_binary_control = RawClient::connect(released.addr, DB).await?;
    json_binary_control
        .send(parse_msg(
            "s",
            "SELECT legacy FROM canary.documents WHERE id = 1",
        ))
        .await?;
    json_binary_control.send(describe_statement("s")).await?;
    json_binary_control
        .send(bind_msg_with_result_format("p", "s", 1))
        .await?;
    json_binary_control.send(execute_msg("p", 0)).await?;
    json_binary_control.send(sync_msg()).await?;
    let json_binary_control_msgs = json_binary_control.read_until_ready().await?;
    assert_served(&json_binary_control_msgs, "binary json poison control");
    assert_canary_present(&json_binary_control, CANARY_EMAIL);

    let mut json_binary_client = RawClient::connect(masked.addr, DB).await?;
    json_binary_client
        .send(parse_msg(
            "s",
            "SELECT legacy FROM canary.documents WHERE id = 1",
        ))
        .await?;
    json_binary_client.send(describe_statement("s")).await?;
    json_binary_client
        .send(bind_msg_with_result_format("p", "s", 1))
        .await?;
    json_binary_client.send(execute_msg("p", 0)).await?;
    json_binary_client.send(sync_msg()).await?;
    let json_binary_msgs = json_binary_client.read_until_ready().await?;
    assert_served(&json_binary_msgs, "binary json");
    assert_no_canary(&json_binary_client, "structure-aware binary json");
    let rows = data_rows(&json_binary_msgs)?;
    let value = rows
        .first()
        .and_then(|row| row.first())
        .and_then(Option::as_ref)
        .expect("one non-NULL binary json field");
    let value: serde_json::Value =
        serde_json::from_slice(value).expect("binary json is unversioned JSON text");
    assert_eq!(
        value,
        serde_json::json!({
            "profile": {
                "email": "***************b2c3",
                "name": "***"
            },
            "public": "Portland",
            "unknown": ""
        }),
        "binary json must carry the exact pointer masks"
    );

    // A JSON string scalar holding an encoded object is how Chatwoot's native
    // JSON + Rails coder mismatch appears on disk. Exercise it in binary too:
    // OID 114 has no version byte, and the string's inner bytes are still
    // sensitive even though no JSON Pointer can enter them.
    let mut encoded_control = RawClient::connect(released.addr, DB).await?;
    encoded_control
        .send(parse_msg(
            "encoded",
            "SELECT encoded FROM canary.documents WHERE id = 1",
        ))
        .await?;
    encoded_control.send(describe_statement("encoded")).await?;
    encoded_control
        .send(bind_msg_with_result_format("encoded_portal", "encoded", 1))
        .await?;
    encoded_control
        .send(execute_msg("encoded_portal", 0))
        .await?;
    encoded_control.send(sync_msg()).await?;
    let encoded_control_msgs = encoded_control.read_until_ready().await?;
    assert_served(
        &encoded_control_msgs,
        "double-encoded binary JSON poison control",
    );
    assert_canary_present(&encoded_control, CANARY_EMAIL);

    let mut encoded_client = RawClient::connect(masked.addr, DB).await?;
    encoded_client
        .send(parse_msg(
            "encoded",
            "SELECT encoded FROM canary.documents WHERE id = 1",
        ))
        .await?;
    encoded_client.send(describe_statement("encoded")).await?;
    encoded_client
        .send(bind_msg_with_result_format("encoded_portal", "encoded", 1))
        .await?;
    encoded_client
        .send(execute_msg("encoded_portal", 0))
        .await?;
    encoded_client.send(sync_msg()).await?;
    let encoded_msgs = encoded_client.read_until_ready().await?;
    assert_served(&encoded_msgs, "double-encoded binary JSON");
    assert_no_canary(&encoded_client, "double-encoded binary JSON");
    let encoded_rows = data_rows(&encoded_msgs)?;
    let encoded_value = encoded_rows
        .first()
        .and_then(|row| row.first())
        .and_then(Option::as_ref)
        .expect("one non-NULL double-encoded binary JSON field");
    let encoded_value: serde_json::Value =
        serde_json::from_slice(encoded_value).expect("binary json is unversioned JSON text");
    assert_eq!(
        encoded_value,
        serde_json::json!(""),
        "double-encoded JSON must retain only its scalar type"
    );
    Ok(())
}

/// Analyst-facing JSON queries return the useful value implied by pointer
/// policy, not merely "something without a canary".
///
/// Every case first runs directly against Postgres. Sensitive cases require
/// the direct value to contain a poison token, proving the SQL reaches the
/// secret and that a refusal/NULL/mask through pgmask is meaningful. The same
/// SQL then runs through the raw-wire client and its one text DataRow is
/// decoded exactly (JSON values compare semantically, not by key order).
#[tokio::test]
async fn json_sql_queries_return_exact_masked_values_with_poison_controls() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, classified_json_document_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;

    let partial_email = "***************b2c3";
    let direct_payload = serde_json::json!({
        "profile": {"email": CANARY_EMAIL, "name": CANARY_NAME},
        "public": "Portland",
        "unknown": CANARY_NOTE,
        "items": [
            {"token": CANARY_TEMP, "city": "Denver"},
            {"token": CANARY_TEMP, "city": "Seattle"}
        ],
        "numeric_object": {
            "0": {"token": CANARY_TEMP},
            "*": {"token": CANARY_TEMP}
        },
        "a/b": {"~key": CANARY_NOTE},
        "n": 99,
        "enabled": true,
        "nothing": null,
        "empty_object": {},
        "empty_array": []
    });
    let masked_payload = serde_json::json!({
        "profile": {"email": partial_email, "name": "***"},
        "public": "Portland",
        "unknown": "",
        "items": [
            {"token": "***", "city": "Denver"},
            {"token": "***", "city": "Seattle"}
        ],
        "numeric_object": {
            "0": {"token": ""},
            "*": {"token": "***"}
        },
        "a/b": {"~key": "***"},
        "n": 0,
        "enabled": false,
        "nothing": null,
        "empty_object": {},
        "empty_array": []
    });
    let cases = vec![
        JsonSqlValueCase {
            name: "whole jsonb document",
            sql: "SELECT payload FROM canary.documents",
            direct: JsonSqlValue::Json(direct_payload.clone()),
            masked: JsonSqlValue::Json(masked_payload.clone()),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "whole json document",
            sql: "SELECT legacy FROM canary.documents",
            direct: JsonSqlValue::Json(serde_json::json!({
                "profile": {"email": CANARY_EMAIL, "name": CANARY_NAME},
                "public": "Portland",
                "unknown": CANARY_NOTE
            })),
            masked: JsonSqlValue::Json(serde_json::json!({
                "profile": {"email": partial_email, "name": "***"},
                "public": "Portland",
                "unknown": ""
            })),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "double-encoded JSON string scalar",
            sql: "SELECT encoded FROM canary.documents",
            direct: JsonSqlValue::Json(serde_json::json!(
                r#"{"submitted_email":"CANARY_EMAIL_a1b2c3"}"#
            )),
            masked: JsonSqlValue::Json(serde_json::json!("")),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "released text leaf",
            sql: "SELECT payload->>'public' FROM canary.documents",
            direct: JsonSqlValue::Text("Portland"),
            masked: JsonSqlValue::Text("Portland"),
            poison: None,
        },
        JsonSqlValueCase {
            name: "masked chained text leaf",
            sql: "SELECT payload->'profile'->>'email' FROM canary.documents",
            direct: JsonSqlValue::Text(CANARY_EMAIL),
            masked: JsonSqlValue::Text(partial_email),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "redacted chained text leaf",
            sql: "SELECT payload->'profile'->>'name' FROM canary.documents",
            direct: JsonSqlValue::Text(CANARY_NAME),
            masked: JsonSqlValue::Text("***"),
            poison: Some(CANARY_NAME),
        },
        JsonSqlValueCase {
            name: "qualified operator syntax masked text leaf",
            sql: "SELECT (payload OPERATOR(pg_catalog.->) 'profile') \
                  OPERATOR(pg_catalog.->>) 'email' FROM canary.documents",
            direct: JsonSqlValue::Text(CANARY_EMAIL),
            masked: JsonSqlValue::Text(partial_email),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "masked hash-path text leaf",
            sql: "SELECT payload #>> '{profile,email}' FROM canary.documents",
            direct: JsonSqlValue::Text(CANARY_EMAIL),
            masked: JsonSqlValue::Text(partial_email),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "masked ARRAY path text leaf",
            sql: "SELECT payload #>> ARRAY['profile','email'] FROM canary.documents",
            direct: JsonSqlValue::Text(CANARY_EMAIL),
            masked: JsonSqlValue::Text(partial_email),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "masked cast ARRAY path text leaf",
            sql: "SELECT payload #>> ARRAY['profile'::text,'email'::text] \
                  FROM canary.documents",
            direct: JsonSqlValue::Text(CANARY_EMAIL),
            masked: JsonSqlValue::Text(partial_email),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "masked extract-path text leaf",
            sql: "SELECT jsonb_extract_path_text(payload, 'profile', 'email') \
                  FROM canary.documents",
            direct: JsonSqlValue::Text(CANARY_EMAIL),
            masked: JsonSqlValue::Text(partial_email),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "qualified masked extract-path text leaf",
            sql: "SELECT pg_catalog.jsonb_extract_path_text(payload, 'profile', 'email') \
                  FROM canary.documents",
            direct: JsonSqlValue::Text(CANARY_EMAIL),
            masked: JsonSqlValue::Text(partial_email),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "cast keys in extract-path text leaf",
            sql: "SELECT jsonb_extract_path_text(payload, 'profile'::text, 'email'::text) \
                  FROM canary.documents",
            direct: JsonSqlValue::Text(CANARY_EMAIL),
            masked: JsonSqlValue::Text(partial_email),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "legacy json masked text leaf",
            sql: "SELECT legacy->'profile'->>'email' FROM canary.documents",
            direct: JsonSqlValue::Text(CANARY_EMAIL),
            masked: JsonSqlValue::Text(partial_email),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "legacy json extract-path text leaf",
            sql: "SELECT json_extract_path_text(legacy, 'profile', 'email') \
                  FROM canary.documents",
            direct: JsonSqlValue::Text(CANARY_EMAIL),
            masked: JsonSqlValue::Text(partial_email),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "legacy json extract-path document",
            sql: "SELECT json_extract_path(legacy, 'profile') FROM canary.documents",
            direct: JsonSqlValue::Json(serde_json::json!({
                "email": CANARY_EMAIL,
                "name": CANARY_NAME
            })),
            masked: JsonSqlValue::Json(serde_json::json!({
                "email": partial_email,
                "name": "***"
            })),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "view-owned masked text leaf",
            sql: "SELECT payload->'profile'->>'email' FROM canary.documents_view",
            direct: JsonSqlValue::Text(CANARY_EMAIL),
            masked: JsonSqlValue::Text(partial_email),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "aliased joined masked text leaf",
            sql: "SELECT d.payload->'profile'->>'email' FROM canary.documents d \
                  JOIN canary.subjects s ON s.id = d.id",
            direct: JsonSqlValue::Text(CANARY_EMAIL),
            masked: JsonSqlValue::Text(partial_email),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "bare extract has one owner across a join",
            sql: "SELECT payload->'profile'->>'email' FROM canary.documents d \
                  JOIN canary.subjects s ON s.id = d.id",
            direct: JsonSqlValue::Text(CANARY_EMAIL),
            masked: JsonSqlValue::Text(partial_email),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "qualified extract owner across a self join",
            sql: "SELECT d1.payload->'profile'->>'email' FROM canary.documents d1 \
                  JOIN canary.documents d2 ON d2.id = d1.id",
            direct: JsonSqlValue::Text(CANARY_EMAIL),
            masked: JsonSqlValue::Text(partial_email),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "cast wrapper keeps masked value",
            sql: "SELECT CAST(payload->'profile'->>'email' AS text) FROM canary.documents",
            direct: JsonSqlValue::Text(CANARY_EMAIL),
            masked: JsonSqlValue::Text(partial_email),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "collation wrapper keeps masked value",
            sql: "SELECT (payload->'profile'->>'email') COLLATE \"C\" \
                  FROM canary.documents",
            direct: JsonSqlValue::Text(CANARY_EMAIL),
            masked: JsonSqlValue::Text(partial_email),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "masked extract with containment predicate in default posture",
            sql: "SELECT payload->'profile'->>'email' FROM canary.documents \
                  WHERE payload @> '{\"public\":\"Portland\"}'",
            direct: JsonSqlValue::Text(CANARY_EMAIL),
            masked: JsonSqlValue::Text(partial_email),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "masked extract with text predicate in default posture",
            sql: "SELECT payload->'profile'->>'email' FROM canary.documents \
                  WHERE payload->>'public' = 'Portland'",
            direct: JsonSqlValue::Text(CANARY_EMAIL),
            masked: JsonSqlValue::Text(partial_email),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "masked extract ordered by itself",
            sql: "SELECT payload->'profile'->>'email' FROM canary.documents \
                  ORDER BY payload->'profile'->>'email'",
            direct: JsonSqlValue::Text(CANARY_EMAIL),
            masked: JsonSqlValue::Text(partial_email),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "distinct masked extract",
            sql: "SELECT DISTINCT payload->'profile'->>'email' FROM canary.documents",
            direct: JsonSqlValue::Text(CANARY_EMAIL),
            masked: JsonSqlValue::Text(partial_email),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "masked extract with limit",
            sql: "SELECT payload->'profile'->>'email' FROM canary.documents LIMIT 1",
            direct: JsonSqlValue::Text(CANARY_EMAIL),
            masked: JsonSqlValue::Text(partial_email),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "unmatched sensitive string becomes SQL NULL",
            sql: "SELECT payload->>'unknown' FROM canary.documents",
            direct: JsonSqlValue::Text(CANARY_NOTE),
            masked: JsonSqlValue::Null,
            poison: Some(CANARY_NOTE),
        },
        JsonSqlValueCase {
            name: "unmatched number text extract becomes SQL NULL",
            sql: "SELECT payload->>'n' FROM canary.documents",
            direct: JsonSqlValue::Text("99"),
            masked: JsonSqlValue::Null,
            poison: None,
        },
        JsonSqlValueCase {
            name: "unmatched boolean text extract becomes SQL NULL",
            sql: "SELECT payload->>'enabled' FROM canary.documents",
            direct: JsonSqlValue::Text("true"),
            masked: JsonSqlValue::Null,
            poison: None,
        },
        JsonSqlValueCase {
            name: "unmatched number document extract keeps type",
            sql: "SELECT payload->'n' FROM canary.documents",
            direct: JsonSqlValue::Json(serde_json::json!(99)),
            masked: JsonSqlValue::Json(serde_json::json!(0)),
            poison: None,
        },
        JsonSqlValueCase {
            name: "unmatched boolean document extract keeps type",
            sql: "SELECT payload->'enabled' FROM canary.documents",
            direct: JsonSqlValue::Json(serde_json::json!(true)),
            masked: JsonSqlValue::Json(serde_json::json!(false)),
            poison: None,
        },
        JsonSqlValueCase {
            name: "explicit JSON null document extract stays JSON null",
            sql: "SELECT payload->'nothing' FROM canary.documents",
            direct: JsonSqlValue::Json(serde_json::Value::Null),
            masked: JsonSqlValue::Json(serde_json::Value::Null),
            poison: None,
        },
        JsonSqlValueCase {
            name: "explicit JSON null text extract is SQL NULL",
            sql: "SELECT payload->>'nothing' FROM canary.documents",
            direct: JsonSqlValue::Null,
            masked: JsonSqlValue::Null,
            poison: None,
        },
        JsonSqlValueCase {
            name: "missing document path is SQL NULL",
            sql: "SELECT payload->'missing' FROM canary.documents",
            direct: JsonSqlValue::Null,
            masked: JsonSqlValue::Null,
            poison: None,
        },
        JsonSqlValueCase {
            name: "missing text path is SQL NULL",
            sql: "SELECT payload->>'missing' FROM canary.documents",
            direct: JsonSqlValue::Null,
            masked: JsonSqlValue::Null,
            poison: None,
        },
        JsonSqlValueCase {
            name: "empty object document extract preserves shape",
            sql: "SELECT payload->'empty_object' FROM canary.documents",
            direct: JsonSqlValue::Json(serde_json::json!({})),
            masked: JsonSqlValue::Json(serde_json::json!({})),
            poison: None,
        },
        JsonSqlValueCase {
            name: "empty array document extract preserves shape",
            sql: "SELECT payload->'empty_array' FROM canary.documents",
            direct: JsonSqlValue::Json(serde_json::json!([])),
            masked: JsonSqlValue::Json(serde_json::json!([])),
            poison: None,
        },
        JsonSqlValueCase {
            name: "empty object text extract follows unmatched SQL NULL policy",
            sql: "SELECT payload->>'empty_object' FROM canary.documents",
            direct: JsonSqlValue::Text("{}"),
            masked: JsonSqlValue::Null,
            poison: None,
        },
        JsonSqlValueCase {
            name: "empty array text extract follows unmatched SQL NULL policy",
            sql: "SELECT payload->>'empty_array' FROM canary.documents",
            direct: JsonSqlValue::Text("[]"),
            masked: JsonSqlValue::Null,
            poison: None,
        },
        JsonSqlValueCase {
            name: "released array city",
            sql: "SELECT payload->'items'->0->>'city' FROM canary.documents",
            direct: JsonSqlValue::Text("Denver"),
            masked: JsonSqlValue::Text("Denver"),
            poison: None,
        },
        JsonSqlValueCase {
            name: "second released array city",
            sql: "SELECT payload->'items'->1->>'city' FROM canary.documents",
            direct: JsonSqlValue::Text("Seattle"),
            masked: JsonSqlValue::Text("Seattle"),
            poison: None,
        },
        JsonSqlValueCase {
            name: "masked array token text leaf",
            sql: "SELECT payload->'items'->0->>'token' FROM canary.documents",
            direct: JsonSqlValue::Text(CANARY_TEMP),
            masked: JsonSqlValue::Text("***"),
            poison: Some(CANARY_TEMP),
        },
        JsonSqlValueCase {
            name: "masked second array token text leaf",
            sql: "SELECT payload->'items'->1->>'token' FROM canary.documents",
            direct: JsonSqlValue::Text(CANARY_TEMP),
            masked: JsonSqlValue::Text("***"),
            poison: Some(CANARY_TEMP),
        },
        JsonSqlValueCase {
            name: "masked array token document scalar",
            sql: "SELECT payload->'items'->0->'token' FROM canary.documents",
            direct: JsonSqlValue::Json(serde_json::json!(CANARY_TEMP)),
            masked: JsonSqlValue::Json(serde_json::json!("***")),
            poison: Some(CANARY_TEMP),
        },
        JsonSqlValueCase {
            name: "masked array object",
            sql: "SELECT payload->'items'->0 FROM canary.documents",
            direct: JsonSqlValue::Json(serde_json::json!({
                "token": CANARY_TEMP,
                "city": "Denver"
            })),
            masked: JsonSqlValue::Json(serde_json::json!({
                "token": "***",
                "city": "Denver"
            })),
            poison: Some(CANARY_TEMP),
        },
        JsonSqlValueCase {
            name: "masked whole array",
            sql: "SELECT payload->'items' FROM canary.documents",
            direct: JsonSqlValue::Json(serde_json::json!([
                {"token": CANARY_TEMP, "city": "Denver"},
                {"token": CANARY_TEMP, "city": "Seattle"}
            ])),
            masked: JsonSqlValue::Json(serde_json::json!([
                {"token": "***", "city": "Denver"},
                {"token": "***", "city": "Seattle"}
            ])),
            poison: Some(CANARY_TEMP),
        },
        JsonSqlValueCase {
            name: "masked profile object",
            sql: "SELECT payload->'profile' FROM canary.documents",
            direct: JsonSqlValue::Json(serde_json::json!({
                "email": CANARY_EMAIL,
                "name": CANARY_NAME
            })),
            masked: JsonSqlValue::Json(serde_json::json!({
                "email": partial_email,
                "name": "***"
            })),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "masked hash-path profile object",
            sql: "SELECT payload #> '{profile}' FROM canary.documents",
            direct: JsonSqlValue::Json(serde_json::json!({
                "email": CANARY_EMAIL,
                "name": CANARY_NAME
            })),
            masked: JsonSqlValue::Json(serde_json::json!({
                "email": partial_email,
                "name": "***"
            })),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "masked ARRAY path profile object",
            sql: "SELECT payload #> ARRAY['profile'] FROM canary.documents",
            direct: JsonSqlValue::Json(serde_json::json!({
                "email": CANARY_EMAIL,
                "name": CANARY_NAME
            })),
            masked: JsonSqlValue::Json(serde_json::json!({
                "email": partial_email,
                "name": "***"
            })),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "masked extract-path profile object",
            sql: "SELECT jsonb_extract_path(payload, 'profile') FROM canary.documents",
            direct: JsonSqlValue::Json(serde_json::json!({
                "email": CANARY_EMAIL,
                "name": CANARY_NAME
            })),
            masked: JsonSqlValue::Json(serde_json::json!({
                "email": partial_email,
                "name": "***"
            })),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "subscripted profile object",
            sql: "SELECT payload['profile'] FROM canary.documents",
            direct: JsonSqlValue::Json(serde_json::json!({
                "email": CANARY_EMAIL,
                "name": CANARY_NAME
            })),
            masked: JsonSqlValue::Json(serde_json::json!({
                "email": partial_email,
                "name": "***"
            })),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "chained subscripted email leaf stays json",
            sql: "SELECT payload['profile']['email'] FROM canary.documents",
            direct: JsonSqlValue::Json(serde_json::json!(CANARY_EMAIL)),
            masked: JsonSqlValue::Json(serde_json::json!(partial_email)),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "subscript then text operator",
            sql: "SELECT payload['profile']->>'email' FROM canary.documents",
            direct: JsonSqlValue::Text(CANARY_EMAIL),
            masked: JsonSqlValue::Text(partial_email),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "operator then subscript",
            sql: "SELECT (payload->'profile')['email'] FROM canary.documents",
            direct: JsonSqlValue::Json(serde_json::json!(CANARY_EMAIL)),
            masked: JsonSqlValue::Json(serde_json::json!(partial_email)),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "quoted numeric object key never inherits array wildcard",
            sql: "SELECT payload->'numeric_object'->'0'->>'token' FROM canary.documents",
            direct: JsonSqlValue::Text(CANARY_TEMP),
            masked: JsonSqlValue::Null,
            poison: Some(CANARY_TEMP),
        },
        JsonSqlValueCase {
            name: "literal object star key uses the star pointer",
            sql: "SELECT payload->'numeric_object'->'*'->>'token' FROM canary.documents",
            direct: JsonSqlValue::Text(CANARY_TEMP),
            masked: JsonSqlValue::Text("***"),
            poison: Some(CANARY_TEMP),
        },
        JsonSqlValueCase {
            name: "RFC 6901 escaped pointer keys work through SQL",
            sql: "SELECT payload->'a/b'->>'~key' FROM canary.documents",
            direct: JsonSqlValue::Text(CANARY_NOTE),
            masked: JsonSqlValue::Text("***"),
            poison: Some(CANARY_NOTE),
        },
        JsonSqlValueCase {
            name: "relation-qualified extract owner",
            sql: "SELECT canary.documents.payload->>'public' FROM canary.documents",
            direct: JsonSqlValue::Text("Portland"),
            masked: JsonSqlValue::Text("Portland"),
            poison: None,
        },
        JsonSqlValueCase {
            name: "extract wrapped by subquery keeps the projected value",
            sql: "SELECT * FROM (SELECT payload->>'public' FROM canary.documents) q",
            direct: JsonSqlValue::Text("Portland"),
            masked: JsonSqlValue::Text("Portland"),
            poison: None,
        },
        JsonSqlValueCase {
            name: "aliased JSON column",
            sql: "SELECT payload AS p FROM canary.documents",
            direct: JsonSqlValue::Json(direct_payload.clone()),
            masked: JsonSqlValue::Json(masked_payload.clone()),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "table-aliased JSON column",
            sql: "SELECT d.payload FROM canary.documents d",
            direct: JsonSqlValue::Json(direct_payload.clone()),
            masked: JsonSqlValue::Json(masked_payload.clone()),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "JSON column through join",
            sql: "SELECT d.payload FROM canary.documents d \
                  JOIN canary.subjects s ON s.id = d.id",
            direct: JsonSqlValue::Json(direct_payload.clone()),
            masked: JsonSqlValue::Json(masked_payload.clone()),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "JSON column through subquery",
            sql: "SELECT payload FROM (SELECT payload FROM canary.documents OFFSET 0) q",
            direct: JsonSqlValue::Json(direct_payload.clone()),
            masked: JsonSqlValue::Json(masked_payload.clone()),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "JSON column through CTE",
            sql: "WITH c AS (SELECT payload FROM canary.documents) SELECT payload FROM c",
            direct: JsonSqlValue::Json(direct_payload.clone()),
            masked: JsonSqlValue::Json(masked_payload.clone()),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "identity jsonb cast",
            sql: "SELECT payload::jsonb FROM canary.documents",
            direct: JsonSqlValue::Json(direct_payload.clone()),
            masked: JsonSqlValue::Json(masked_payload.clone()),
            poison: Some(CANARY_EMAIL),
        },
        JsonSqlValueCase {
            name: "JSON column with containment predicate in default posture",
            sql: "SELECT payload FROM canary.documents \
                  WHERE payload @> '{\"public\":\"Portland\"}'",
            direct: JsonSqlValue::Json(direct_payload.clone()),
            masked: JsonSqlValue::Json(masked_payload.clone()),
            poison: Some(CANARY_EMAIL),
        },
    ];

    for case in cases {
        let direct = simple_query_direct(DB, case.sql).await?;
        assert_single_sql_value(
            &direct,
            &case.direct,
            &format!("{} direct poison", case.name),
        );
        if let Some(poison) = case.poison {
            assert!(
                direct
                    .iter()
                    .flatten()
                    .flatten()
                    .any(|value| value.contains(poison)),
                "{}: direct query did not expose poison {poison:?}: {direct:?}",
                case.name
            );
        }

        let masked = simple_query_round(&mut client, case.sql).await?;
        assert_served(&masked.messages, case.name);
        assert_no_canary_bytes(&masked.received, case.name);
        let rows = masked.text_rows()?;
        assert_single_sql_value(&rows, &case.masked, case.name);
    }

    // One RowDescription carrying released, masked, unmatched, typed, and
    // array-wildcard extracts pins positional alignment across fields. Testing
    // each projection alone would not catch a plan shifted by one slot.
    let sql = "SELECT payload->>'public', \
                      payload->'profile'->>'email', \
                      payload->>'unknown', \
                      payload->>'n', \
                      payload->'items'->0->>'token' \
               FROM canary.documents";
    let direct = simple_query_direct(DB, sql).await?;
    assert_eq!(
        direct,
        vec![vec![
            Some("Portland".into()),
            Some(CANARY_EMAIL.into()),
            Some(CANARY_NOTE.into()),
            Some("99".into()),
            Some(CANARY_TEMP.into()),
        ]],
        "multi-field direct poison control"
    );
    let masked = simple_query_round(&mut client, sql).await?;
    assert_served(&masked.messages, "multi-field JSON projection");
    assert_no_canary_bytes(&masked.received, "multi-field JSON projection");
    assert_eq!(
        masked.text_rows()?,
        vec![vec![
            Some("Portland".into()),
            Some(partial_email.into()),
            None,
            None,
            Some("***".into()),
        ]],
        "JSON expression plans must align with RowDescription positions"
    );

    // Star expansion and a two-column view keep table OID + attnum on every
    // JSON field. The campaign above is one-field; these pin the same pointer
    // policy across a multi-column RowDescription.
    let star = simple_query_round(&mut client, "SELECT * FROM canary.documents").await?;
    assert_served(&star.messages, "star expansion");
    assert_no_canary_bytes(&star.received, "star expansion");
    let star_rows = star.text_rows()?;
    assert_eq!(star_rows.len(), 1, "star expansion rows");
    assert_eq!(star_rows[0].len(), 4, "id, payload, legacy, encoded");
    assert_eq!(star_rows[0][0].as_deref(), Some("1"));
    assert_single_sql_value(
        &[vec![star_rows[0][1].clone()]],
        &JsonSqlValue::Json(masked_payload.clone()),
        "star payload",
    );
    assert_single_sql_value(
        &[vec![star_rows[0][2].clone()]],
        &JsonSqlValue::Json(serde_json::json!({
            "profile": {"email": partial_email, "name": "***"},
            "public": "Portland",
            "unknown": ""
        })),
        "star legacy",
    );
    assert_single_sql_value(
        &[vec![star_rows[0][3].clone()]],
        &JsonSqlValue::Json(serde_json::json!("")),
        "star double-encoded JSON",
    );

    let view = simple_query_round(
        &mut client,
        "SELECT payload, legacy FROM canary.documents_view",
    )
    .await?;
    assert_served(&view.messages, "JSON columns through view");
    assert_no_canary_bytes(&view.received, "JSON columns through view");
    let view_rows = view.text_rows()?;
    assert_eq!(view_rows.len(), 1, "view rows");
    assert_eq!(view_rows[0].len(), 2, "payload, legacy");
    assert_single_sql_value(
        &[vec![view_rows[0][0].clone()]],
        &JsonSqlValue::Json(masked_payload),
        "view payload",
    );
    assert_single_sql_value(
        &[vec![view_rows[0][1].clone()]],
        &JsonSqlValue::Json(serde_json::json!({
            "profile": {"email": partial_email, "name": "***"},
            "public": "Portland",
            "unknown": ""
        })),
        "view legacy",
    );
    Ok(())
}

/// `json_unmatched = "none"` is a deliberate release grant, including text
/// extracts. Pin that disclosure while proving a narrower pointer still wins.
#[tokio::test]
async fn json_unmatched_none_releases_only_unlisted_extracts_by_configuration() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let mut rules = default_rules();
    rules.push(json_rule(
        "canary.documents",
        "payload",
        pgmask::mask::JsonUnmatched::None,
        vec![
            json_field("/profile/email", pgmask::mask::Mask::Redact),
            json_field("/items/*/token", pgmask::mask::Mask::Redact),
            json_field("/numeric_object/*/token", pgmask::mask::Mask::Redact),
        ],
    ));
    let proxy = start_proxy(DB, rules).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;

    let unknown = simple_query_round(
        &mut client,
        "SELECT payload->>'unknown' FROM canary.documents",
    )
    .await?;
    assert_served(&unknown.messages, "json_unmatched none release");
    assert_eq!(
        unknown.text_rows()?,
        vec![vec![Some(CANARY_NOTE.into())]],
        "unlisted text extract is intentionally public"
    );

    let email = simple_query_round(
        &mut client,
        "SELECT payload->'profile'->>'email' FROM canary.documents",
    )
    .await?;
    assert_served(
        &email.messages,
        "pointer override under json_unmatched none",
    );
    assert_no_canary_bytes(
        &email.received,
        "pointer override under json_unmatched none",
    );
    assert_eq!(
        email.text_rows()?,
        vec![vec![Some("***".into())]],
        "explicit pointer must override unmatched release"
    );

    // The runtime parent and post-cast type decide subscript navigation.
    // PostgreSQL uses both bare `0` and `'0'` as index 0 under an array and key
    // "0" under an object. Casts add another inversion: `'0'::int` is an array
    // index while `0::text` is an object key. Under this unmatched-release
    // policy, claiming either shape can release the token instead of applying
    // the explicit wildcard or refusing.
    for (name, sql) in [
        (
            "quoted integer under runtime array",
            "SELECT payload['items']['0']->>'token' FROM canary.documents",
        ),
        (
            "integer under runtime object",
            "SELECT payload['numeric_object'][0]->>'token' FROM canary.documents",
        ),
        (
            "string literal cast to array index",
            "SELECT payload['items']['0'::int]->>'token' FROM canary.documents",
        ),
        (
            "integer literal cast to object key",
            "SELECT payload['numeric_object'][0::text]->>'token' FROM canary.documents",
        ),
    ] {
        let direct = simple_query_direct(DB, sql).await?;
        assert_eq!(
            direct,
            vec![vec![Some(CANARY_TEMP.into())]],
            "{name} poison control"
        );
        let refused = simple_query_round(&mut client, sql).await?;
        assert_refused_bytes(&refused.received, name);
        assert_no_canary_bytes(&refused.received, name);
    }
    Ok(())
}

/// Every refused JSON shape is valid SQL that exposes a poison value on the
/// backend. This distinguishes a pgmask refusal from a PostgreSQL parse/type
/// error and from a query that never reached sensitive data.
#[tokio::test]
async fn json_sql_refusals_have_direct_poison_controls() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, classified_json_document_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;

    let cases = [
        (
            "named extract alias through subquery",
            "SELECT email FROM (SELECT payload->'profile'->>'email' AS email \
             FROM canary.documents) q",
            CANARY_EMAIL,
        ),
        (
            "named extract alias through CTE",
            "WITH q AS (SELECT payload->'profile'->>'email' AS email \
             FROM canary.documents) SELECT email FROM q",
            CANARY_EMAIL,
        ),
        (
            "runtime operator key",
            "SELECT payload->>(CASE WHEN id = 1 THEN 'unknown' ELSE 'public' END) \
             FROM canary.documents",
            CANARY_NOTE,
        ),
        (
            "scalar-subquery operator key",
            "SELECT payload->>(SELECT 'unknown') FROM canary.documents",
            CANARY_NOTE,
        ),
        (
            "runtime ARRAY path element",
            "SELECT payload #>> ARRAY['profile', CASE WHEN id = 1 THEN 'email' ELSE 'name' END] \
             FROM canary.documents",
            CANARY_EMAIL,
        ),
        (
            "ambiguous text path through an array wildcard",
            "SELECT payload #>> '{items,0,token}' FROM canary.documents",
            CANARY_TEMP,
        ),
        (
            "ambiguous extract-path function through an array wildcard",
            "SELECT jsonb_extract_path_text(payload, 'items', '0', 'token') \
             FROM canary.documents",
            CANARY_TEMP,
        ),
        (
            "negative array index",
            "SELECT payload->'items'->-1->>'token' FROM canary.documents",
            CANARY_TEMP,
        ),
        (
            "negative array subscript",
            "SELECT payload['items'][-1]->>'token' FROM canary.documents",
            CANARY_TEMP,
        ),
        (
            "protected object serialized by text operator",
            "SELECT payload->>'profile' FROM canary.documents",
            CANARY_EMAIL,
        ),
        (
            "protected object serialized by hash path",
            "SELECT payload #>> '{profile}' FROM canary.documents",
            CANARY_EMAIL,
        ),
        (
            "protected object serialized by extract-path function",
            "SELECT jsonb_extract_path_text(payload, 'profile') FROM canary.documents",
            CANARY_EMAIL,
        ),
        (
            "legacy protected object serialized by text operator",
            "SELECT legacy->>'profile' FROM canary.documents",
            CANARY_EMAIL,
        ),
        (
            "JSONPath query first",
            "SELECT jsonb_path_query_first(payload, '$.profile.email') \
             FROM canary.documents",
            CANARY_EMAIL,
        ),
        (
            "JSONPath set-returning query",
            "SELECT jsonb_path_query(payload, '$.items[*].token') \
             FROM canary.documents",
            CANARY_TEMP,
        ),
        (
            "JSONPath query array",
            "SELECT jsonb_path_query_array(payload, '$.items[*].token') \
             FROM canary.documents",
            CANARY_TEMP,
        ),
        (
            "pretty serialization",
            "SELECT jsonb_pretty(payload) FROM canary.documents",
            CANARY_EMAIL,
        ),
        (
            "object expansion",
            "SELECT jsonb_each(payload) FROM canary.documents",
            CANARY_EMAIL,
        ),
        (
            "array expansion",
            "SELECT jsonb_array_elements(payload->'items') FROM canary.documents",
            CANARY_TEMP,
        ),
        (
            "object construction around an extract",
            "SELECT jsonb_build_object('email', payload->'profile'->>'email') \
             FROM canary.documents",
            CANARY_EMAIL,
        ),
        (
            "document concatenation",
            "SELECT payload || '{\"added\":true}'::jsonb FROM canary.documents",
            CANARY_EMAIL,
        ),
        (
            "document deletion",
            "SELECT payload - 'public' FROM canary.documents",
            CANARY_EMAIL,
        ),
        (
            "document path deletion",
            "SELECT payload #- '{public}' FROM canary.documents",
            CANARY_EMAIL,
        ),
        (
            "document mutation",
            "SELECT jsonb_set(payload, '{public}', '\"changed\"') FROM canary.documents",
            CANARY_EMAIL,
        ),
        (
            "document text cast",
            "SELECT payload::text FROM canary.documents",
            CANARY_EMAIL,
        ),
        (
            "coalesce wrapper around extract",
            "SELECT COALESCE(payload->'profile'->>'email', '') FROM canary.documents",
            CANARY_EMAIL,
        ),
        (
            "case wrapper around extract",
            "SELECT CASE WHEN id = 1 THEN payload->'profile'->>'email' END \
             FROM canary.documents",
            CANARY_EMAIL,
        ),
        (
            "upper wrapper around extract",
            "SELECT upper(payload->'profile'->>'email') FROM canary.documents",
            "CANARY_EMAIL_",
        ),
        (
            "scalar subquery projection",
            "SELECT (SELECT payload->'profile'->>'email' \
             FROM canary.documents LIMIT 1)",
            CANARY_EMAIL,
        ),
        (
            "JSON aggregate",
            "SELECT jsonb_agg(payload) FROM canary.documents",
            CANARY_EMAIL,
        ),
        (
            "JSON set operation",
            "SELECT payload FROM canary.documents \
             UNION ALL SELECT payload FROM canary.documents",
            CANARY_EMAIL,
        ),
        (
            "JSON EXCEPT operation",
            "SELECT payload FROM canary.documents \
             EXCEPT SELECT payload FROM canary.documents WHERE id = 0",
            CANARY_EMAIL,
        ),
        (
            "JSON INTERSECT operation",
            "SELECT payload FROM canary.documents INTERSECT \
             SELECT payload FROM canary.documents",
            CANARY_EMAIL,
        ),
        (
            "extract set operation",
            "SELECT payload->'profile'->>'email' FROM canary.documents \
             UNION ALL SELECT payload->'profile'->>'email' FROM canary.documents",
            CANARY_EMAIL,
        ),
        (
            "JSON subscript dynamic key",
            "SELECT payload[CASE WHEN id = 1 THEN 'unknown' ELSE 'public' END] \
             FROM canary.documents",
            CANARY_NOTE,
        ),
        (
            "integer subscript at array wildcard",
            "SELECT payload['items'][0]->>'token' FROM canary.documents",
            CANARY_TEMP,
        ),
        (
            "quoted integer subscript at array wildcard",
            "SELECT payload['items']['0']->>'token' FROM canary.documents",
            CANARY_TEMP,
        ),
        (
            "integer subscript at numeric object wildcard",
            "SELECT payload['numeric_object'][0]->>'token' FROM canary.documents",
            CANARY_TEMP,
        ),
        (
            "quoted integer subscript at numeric object wildcard",
            "SELECT payload['numeric_object']['0']->>'token' FROM canary.documents",
            CANARY_TEMP,
        ),
        (
            "json to jsonb cast",
            "SELECT legacy::jsonb FROM canary.documents",
            CANARY_EMAIL,
        ),
        (
            "json aggregate",
            "SELECT json_agg(payload) FROM canary.documents",
            CANARY_EMAIL,
        ),
        (
            "to_jsonb constructor",
            "SELECT to_jsonb(payload) FROM canary.documents",
            CANARY_EMAIL,
        ),
        (
            "to_json row constructor",
            "SELECT to_json(d) FROM canary.documents d",
            CANARY_EMAIL,
        ),
        (
            "row_to_json constructor",
            "SELECT row_to_json(d) FROM canary.documents d",
            CANARY_EMAIL,
        ),
        (
            "jsonb_build_object around a document",
            "SELECT jsonb_build_object('p', payload) FROM canary.documents",
            CANARY_EMAIL,
        ),
        (
            "lateral array expansion",
            "SELECT * FROM canary.documents, \
             LATERAL jsonb_array_elements(payload->'items') AS elem",
            CANARY_TEMP,
        ),
        (
            "ambiguous document array path",
            "SELECT payload #> '{items,0}' FROM canary.documents",
            CANARY_TEMP,
        ),
        (
            "ambiguous numeric object path",
            "SELECT payload #>> '{numeric_object,0,token}' FROM canary.documents",
            CANARY_TEMP,
        ),
    ];

    for (name, sql, poison) in cases {
        let direct = simple_query_direct(DB, sql).await?;
        assert!(
            direct
                .iter()
                .flatten()
                .flatten()
                .any(|value| value.contains(poison)),
            "{name}: direct poison control did not expose {poison:?}: {direct:?}"
        );

        let masked = simple_query_round(&mut client, sql).await?;
        assert_refused_bytes(&masked.received, name);
        assert_no_canary_bytes(&masked.received, name);
    }
    Ok(())
}

/// Protocol and posture leftovers that the simple-query value/refusal
/// campaigns cannot cover: `search_path` resolution, a dynamic key that
/// yields SQL NULL on the backend (so it has no poison token), binary Bind,
/// and hostile-posture predicate oracles.
#[tokio::test]
async fn json_sql_search_path_binary_and_hostile_posture() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let rules = classified_json_document_rules();
    let proxy = start_proxy(DB, rules.clone()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;

    // Make the unqualified relation real on this backend session. Otherwise
    // PostgreSQL's own undefined-table error would pass the no-canary check
    // without exercising pgmask's search_path refusal.
    client.simple_query("SET search_path = canary").await?;
    let unqualified = "SELECT payload->'profile'->>'email' FROM documents";
    let direct =
        simple_query_direct(DB, &format!("SET search_path = canary; {unqualified}")).await?;
    assert!(
        direct
            .iter()
            .flatten()
            .flatten()
            .any(|value| value.contains(CANARY_EMAIL)),
        "unqualified relation poison control: {direct:?}"
    );
    let refused = simple_query_round(&mut client, unqualified).await?;
    assert_refused_bytes(&refused.received, "unqualified relation");
    assert_no_canary_bytes(&refused.received, "unqualified relation");

    // Dynamic keys are opaque. The backend returns SQL NULL here (id::text is
    // "1", and payload has no such key), so there is no poison token to demand.
    let dynamic = simple_query_round(
        &mut client,
        "SELECT payload->(id::text) FROM canary.documents",
    )
    .await?;
    assert_refused_bytes(&dynamic.received, "dynamic key");
    assert_no_canary_bytes(&dynamic.received, "dynamic key");

    // Text-family binary results use the same bytes, but this goes through
    // Parse/Describe/Bind so format planning is exercised on an extract.
    let mut binary = RawClient::connect(proxy.addr, DB).await?;
    binary
        .send(parse_msg(
            "json_extract",
            "SELECT payload->'profile'->>'email' FROM canary.documents",
        ))
        .await?;
    binary.send(describe_statement("json_extract")).await?;
    binary
        .send(bind_msg_with_result_format(
            "json_portal",
            "json_extract",
            1,
        ))
        .await?;
    binary.send(execute_msg("json_portal", 0)).await?;
    binary.send(sync_msg()).await?;
    let messages = binary.read_until_ready().await?;
    assert_served(&messages, "binary JSON text extract");
    assert_no_canary(&binary, "binary JSON text extract");
    let rows = data_rows(&messages)?;
    assert_eq!(rows.len(), 1, "binary JSON text extract rows");
    assert_eq!(rows[0].len(), 1, "binary JSON text extract fields");
    assert_eq!(
        rows[0][0].as_deref(),
        Some(b"***************b2c3".as_slice()),
        "binary text-family result must contain the exact partial mask"
    );

    let mut binary_document = RawClient::connect(proxy.addr, DB).await?;
    binary_document
        .send(parse_msg(
            "json_document",
            "SELECT payload->'profile' FROM canary.documents",
        ))
        .await?;
    binary_document
        .send(describe_statement("json_document"))
        .await?;
    binary_document
        .send(bind_msg_with_result_format(
            "json_document_portal",
            "json_document",
            1,
        ))
        .await?;
    binary_document
        .send(execute_msg("json_document_portal", 0))
        .await?;
    binary_document.send(sync_msg()).await?;
    let messages = binary_document.read_until_ready().await?;
    assert_served(&messages, "binary JSON document extract");
    assert_no_canary(&binary_document, "binary JSON document extract");
    let rows = data_rows(&messages)?;
    let value = rows
        .first()
        .and_then(|row| row.first())
        .and_then(Option::as_ref)
        .expect("one non-NULL binary JSON document field");
    assert_eq!(value.first(), Some(&1), "binary jsonb version");
    let value: serde_json::Value =
        serde_json::from_slice(&value[1..]).expect("binary jsonb JSON payload");
    assert_eq!(
        value,
        serde_json::json!({
            "email": "***************b2c3",
            "name": "***"
        }),
        "binary JSON document extract must carry the exact pointer masks"
    );

    // Hostile posture still credits one literal extract as the projection, but
    // rejects a second mention of the masked document in a predicate.
    let hostile = start_proxy_hostile(DB, rules).await?;
    let mut hostile_client = RawClient::connect(hostile.addr, DB).await?;
    let projection = simple_query_round(
        &mut hostile_client,
        "SELECT payload->'profile'->>'email' FROM canary.documents",
    )
    .await?;
    assert_served(&projection.messages, "hostile literal JSON projection");
    assert_no_canary_bytes(&projection.received, "hostile literal JSON projection");
    assert_eq!(
        projection.text_rows()?,
        vec![vec![Some("***************b2c3".into())]],
        "hostile posture must still return the exact pointer mask"
    );

    let subscript_projection = simple_query_round(
        &mut hostile_client,
        "SELECT payload['profile']->>'email' FROM canary.documents",
    )
    .await?;
    assert_served(
        &subscript_projection.messages,
        "hostile literal JSON subscript",
    );
    assert_no_canary_bytes(
        &subscript_projection.received,
        "hostile literal JSON subscript",
    );
    assert_eq!(
        subscript_projection.text_rows()?,
        vec![vec![Some("***************b2c3".into())]],
        "hostile posture must credit the subscript's source column"
    );

    let predicate_sql = "SELECT payload->'profile'->>'email' FROM canary.documents \
                         WHERE payload @> '{\"public\":\"Portland\"}'";
    let direct = simple_query_direct(DB, predicate_sql).await?;
    assert!(
        direct
            .iter()
            .flatten()
            .flatten()
            .any(|value| value.contains(CANARY_EMAIL)),
        "hostile predicate poison control: {direct:?}"
    );
    let predicate = simple_query_round(&mut hostile_client, predicate_sql).await?;
    assert_refused_bytes(&predicate.received, "hostile JSON predicate oracle");
    assert_no_canary_bytes(&predicate.received, "hostile JSON predicate oracle");
    Ok(())
}

#[tokio::test]
async fn pipelined_json_portals_stay_masked() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, classified_json_document_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;
    let mut buf = Vec::new();
    for msg in [
        parse_msg("a", "SELECT payload FROM canary.documents"),
        parse_msg("b", "SELECT legacy FROM canary.documents"),
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
    assert_served(&msgs, "pipelined json portals");
    assert_no_canary(&client, "pipelined json portals");
    Ok(())
}

#[tokio::test]
async fn json_leaf_type_mismatch_refuses_the_wire_result_set() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let mut email = json_field("/profile/email", pgmask::mask::Mask::Partial);
    email.params.keep = Some(4);
    let mut rules = default_rules();
    rules.push(json_rule(
        "canary.documents",
        "payload",
        pgmask::mask::JsonUnmatched::Null,
        vec![
            json_field("/profile", pgmask::mask::Mask::None),
            email,
            json_field("/profile/name", pgmask::mask::Mask::Redact),
            json_field("/n", pgmask::mask::Mask::Partial),
        ],
    ));
    let proxy = start_proxy(DB, rules).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;
    client
        .simple_query("SELECT payload FROM canary.documents")
        .await?;
    assert_refused(&client, "partial mask on JSON number leaf");
    assert_no_canary(&client, "partial mask on JSON number leaf");
    Ok(())
}

#[tokio::test]
async fn json_document_byte_and_depth_limits_refuse_before_rows_cross() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;

    let make_rules = |max_bytes: usize, max_depth: usize| {
        let mut rules = default_rules();
        let mut document = json_rule(
            "canary.documents",
            "payload",
            pgmask::mask::JsonUnmatched::Null,
            vec![
                json_field("/profile/email", pgmask::mask::Mask::Redact),
                json_field("/public", pgmask::mask::Mask::None),
            ],
        );
        document.params.json_max_bytes = Some(max_bytes);
        document.params.json_max_depth = Some(max_depth);
        rules.push(document);
        rules
    };

    // Positive control: the same document and pointer policy are served when
    // the limits cover it, so the two refusals below are exercising limits.
    let control = start_proxy(DB, make_rules(1_048_576, 64)).await?;
    let mut control_client = RawClient::connect(control.addr, DB).await?;
    let messages = control_client
        .simple_query("SELECT payload FROM canary.documents")
        .await?;
    assert_served(&messages, "JSON limit positive control");
    assert_no_canary(&control_client, "JSON limit positive control");

    let byte_limited = start_proxy(DB, make_rules(32, 64)).await?;
    let mut byte_client = RawClient::connect(byte_limited.addr, DB).await?;
    byte_client
        .simple_query("SELECT payload FROM canary.documents")
        .await?;
    assert_refused(&byte_client, "JSON byte limit");
    assert_no_canary(&byte_client, "JSON byte limit");

    let mut byte_extract_client = RawClient::connect(byte_limited.addr, DB).await?;
    let byte_extract = simple_query_round(
        &mut byte_extract_client,
        "SELECT payload->'profile' FROM canary.documents",
    )
    .await?;
    assert_refused_bytes(&byte_extract.received, "JSON extract byte limit");
    assert_no_canary_bytes(&byte_extract.received, "JSON extract byte limit");

    let depth_limited = start_proxy(DB, make_rules(1_048_576, 2)).await?;
    let mut depth_client = RawClient::connect(depth_limited.addr, DB).await?;
    depth_client
        .simple_query("SELECT payload FROM canary.documents")
        .await?;
    assert_refused(&depth_client, "JSON depth limit");
    assert_no_canary(&depth_client, "JSON depth limit");

    let extract_depth_limited = start_proxy(DB, make_rules(1_048_576, 1)).await?;
    let mut depth_extract_client = RawClient::connect(extract_depth_limited.addr, DB).await?;
    let depth_extract = simple_query_round(
        &mut depth_extract_client,
        "SELECT payload->'items' FROM canary.documents",
    )
    .await?;
    assert_refused_bytes(&depth_extract.received, "JSON extract depth limit");
    assert_no_canary_bytes(&depth_extract.received, "JSON extract depth limit");
    Ok(())
}

// --- Bypass: paths that emit rows without a RowDescription ------------------

#[tokio::test]
async fn copy_to_stdout_cannot_leak() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;
    // COPY is refused by the read-only allowlist. One proxy and connection are
    // sufficient because each frontend refusal completes with ReadyForQuery.
    assert_sql_cases(
        &mut client,
        &[
            SqlCase::refused("whole table text COPY", "COPY canary.subjects TO STDOUT"),
            SqlCase::refused(
                "query text COPY",
                "COPY (SELECT email FROM canary.subjects) TO STDOUT",
            ),
            SqlCase::refused(
                "selected columns CSV COPY",
                "COPY canary.subjects (email, name) TO STDOUT WITH CSV",
            ),
            SqlCase::refused(
                "whole table binary COPY",
                "COPY canary.subjects TO STDOUT WITH (FORMAT binary)",
            ),
            SqlCase::refused("whole JSON table COPY", "COPY canary.documents TO STDOUT"),
            SqlCase::refused(
                "JSON query COPY",
                "COPY (SELECT payload FROM canary.documents) TO STDOUT",
            ),
        ],
    )
    .await?;
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

/// After PortalSuspended, a *different* named portal's DataRows must not
/// inherit the paused plan.
///
/// Measured live on the GUI catalog: `Execute` of
/// `SELECT ship_city, id …` with `max_rows=1` (released columns), then
/// `SELECT email, name …` (same arity) served `user1@example.com` through
/// `Vetted::unmasked_row`. The proxy still named the suspended portal as
/// `streaming_plan`. Postgres does run the second portal; the comment that
/// it refuses was wrong. Same leak for binary Bind, a same-Sync pipeline,
/// and a mixed plan (only the passthrough slots).
///
/// Either a masked row or a `pgmask:` refusal is fail-closed. Cleartext
/// canaries are not.
#[tokio::test]
async fn a_different_portal_after_suspend_does_not_inherit_the_stale_plan() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;

    // Sequential Sync: the GUI repro. Passthrough city,id then classified
    // email,name — same arity, so a stale all-passthrough plan forwards the
    // second row unchanged.
    client
        .send(parse_msg(
            "s1",
            "SELECT city, id FROM canary.subjects ORDER BY id",
        ))
        .await?;
    client.send(describe_statement("s1")).await?;
    client.send(bind_msg("p1", "s1")).await?;
    client.send(execute_msg("p1", 1)).await?;
    client.send(sync_msg()).await?;
    let _ = client.read_until_ready_or_eof().await?;

    client
        .send(parse_msg(
            "s2",
            "SELECT email, name FROM canary.subjects WHERE id = 1",
        ))
        .await?;
    client.send(describe_statement("s2")).await?;
    client.send(bind_msg("p2", "s2")).await?;
    client.send(execute_msg("p2", 0)).await?;
    client.send(sync_msg()).await?;
    let msgs = client.read_until_ready_or_eof().await?;
    assert_exercised(&msgs, &client, "classified portal after suspend");
    assert_no_canary(&client, "classified portal after suspend");

    // Same-Sync pipeline: Execute p_pass max_rows=1 then Execute p_mask
    // before reading PortalSuspended.
    client = RawClient::connect(proxy.addr, DB).await?;
    let mut buf = Vec::new();
    for msg in [
        parse_msg("s1", "SELECT city, id FROM canary.subjects ORDER BY id"),
        parse_msg("s2", "SELECT email, name FROM canary.subjects WHERE id = 1"),
        describe_statement("s1"),
        describe_statement("s2"),
        bind_msg("p1", "s1"),
        bind_msg("p2", "s2"),
        execute_msg("p1", 1),
        execute_msg("p2", 0),
        sync_msg(),
    ] {
        buf.extend_from_slice(&msg.encode());
    }
    client.send_raw(&buf).await?;
    let msgs = client.read_until_ready_or_eof().await?;
    assert_exercised(&msgs, &client, "pipelined classified portal after suspend");
    assert_no_canary(&client, "pipelined classified portal after suspend");

    // Binary Bind of the classified portal after a text suspend.
    client = RawClient::connect(proxy.addr, DB).await?;
    client
        .send(parse_msg(
            "s1",
            "SELECT city, id FROM canary.subjects ORDER BY id",
        ))
        .await?;
    client.send(describe_statement("s1")).await?;
    client.send(bind_msg("p1", "s1")).await?;
    client.send(execute_msg("p1", 1)).await?;
    client.send(sync_msg()).await?;
    let _ = client.read_until_ready_or_eof().await?;

    client
        .send(parse_msg(
            "s2",
            "SELECT email, name FROM canary.subjects WHERE id = 1",
        ))
        .await?;
    client.send(describe_statement("s2")).await?;
    client
        .send(bind_msg_with_result_format("p2", "s2", 1))
        .await?;
    client.send(execute_msg("p2", 0)).await?;
    client.send(sync_msg()).await?;
    let msgs = client.read_until_ready_or_eof().await?;
    assert_exercised(&msgs, &client, "binary classified portal after suspend");
    assert_no_canary(&client, "binary classified portal after suspend");
    Ok(())
}

/// Failed resume of a suspended named portal after Sync must not leak the
/// next portal's rows.
///
/// Sibling of the 0.1.97 leak. Sync without BEGIN ends the implicit
/// transaction; Postgres destroys named portal A (`SQLSTATE 34000`). Resume
/// cleared `suspended` but left A as a zombie `pending_executes` owner.
/// The next classified portal (`email, name`, same arity) was judged with
/// A's all-passthrough plan and served through `Vetted::unmasked_row`.
///
/// Either a masked row or a `pgmask:` refusal is fail-closed. Cleartext
/// canaries are not.
#[tokio::test]
async fn a_failed_portal_resume_after_sync_does_not_leak_the_next_portal() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;

    client
        .send(parse_msg(
            "s1",
            "SELECT city, id FROM canary.subjects ORDER BY id",
        ))
        .await?;
    client.send(describe_statement("s1")).await?;
    client.send(bind_msg("A", "s1")).await?;
    client.send(execute_msg("A", 1)).await?;
    client.send(sync_msg()).await?;
    let _ = client.read_until_ready_or_eof().await?;

    // Resume of A: the implicit transaction ended, portal is gone.
    client.send(execute_msg("A", 0)).await?;
    client.send(sync_msg()).await?;
    let _ = client.read_until_ready_or_eof().await?;
    assert!(
        client.received_text().contains("34000"),
        "the resume must fail because Sync destroyed the portal; got:\n{}",
        client.received_text()
    );

    client
        .send(parse_msg(
            "s2",
            "SELECT email, name FROM canary.subjects WHERE id = 1",
        ))
        .await?;
    client.send(describe_statement("s2")).await?;
    client.send(bind_msg("B", "s2")).await?;
    client.send(execute_msg("B", 0)).await?;
    client.send(sync_msg()).await?;
    let msgs = client.read_until_ready_or_eof().await?;
    assert_exercised(&msgs, &client, "classified portal after 34000 resume");
    assert_no_canary(&client, "classified portal after 34000 resume");
    Ok(())
}

/// Later-epoch ErrorResponse after PortalSuspended+Idle must not leak
/// the next portal's rows.
///
/// H10a: `Execute A max_rows=1 Sync` (city|id passthrough, Idle), Query
/// `SELECT 1/0` (22012), then Execute B (`email, name`, same arity).
/// The resume-only stamp closed only 34000 on A's own Execute; this
/// error is not that Execute. Keep the 34000-resume and A-then-B tests;
/// they stay closed.
///
/// Either a masked row or a `pgmask:` refusal is fail-closed. Cleartext
/// canaries are not.
#[tokio::test]
async fn a_simple_query_error_after_suspend_does_not_leak_the_next_portal() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;

    client
        .send(parse_msg(
            "s1",
            "SELECT city, id FROM canary.subjects ORDER BY id",
        ))
        .await?;
    client.send(describe_statement("s1")).await?;
    client.send(bind_msg("A", "s1")).await?;
    client.send(execute_msg("A", 1)).await?;
    client.send(sync_msg()).await?;
    let _ = client.read_until_ready_or_eof().await?;

    let _ = client.simple_query("SELECT 1/0").await?;

    client
        .send(parse_msg(
            "s2",
            "SELECT email, name FROM canary.subjects WHERE id = 1",
        ))
        .await?;
    client.send(describe_statement("s2")).await?;
    client.send(bind_msg("B", "s2")).await?;
    client.send(execute_msg("B", 0)).await?;
    client.send(sync_msg()).await?;
    let msgs = client.read_until_ready_or_eof().await?;
    assert_exercised(
        &msgs,
        &client,
        "classified portal after 1/0 following suspend",
    );
    assert_no_canary(&client, "classified portal after 1/0 following suspend");
    Ok(())
}

/// Rebinding the same portal before CommandComplete must not leak the
/// first Execute's rows.
///
/// Sibling of the 0.1.97 PortalSuspended leak, without a suspend.
/// `Bind p s_class; Execute p 0; Bind p s_pass; Execute p 0; Sync` let
/// the second Bind overwrite `portal_plans[p]` while `execute` treated
/// the second Execute as a resume. `streaming_plan` applied the
/// all-passthrough plan to the classified first row;
/// `Vetted::unmasked_row` released the canaries. Unnamed portal `""`
/// and binary Bind leaked the same way. Pass-then-class over-masked
/// (fail-closed). Two different portal names in one Sync were already
/// safe.
///
/// Either a masked row or a `pgmask:` refusal is fail-closed. Cleartext
/// canaries are not.
#[tokio::test]
async fn rebinding_the_same_portal_before_complete_does_not_leak() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;

    // Class then pass on one named portal, one Sync.
    let mut buf = Vec::new();
    for msg in [
        parse_msg("s1", "SELECT email, name FROM canary.subjects WHERE id = 1"),
        parse_msg("s2", "SELECT city, id FROM canary.subjects WHERE id = 1"),
        describe_statement("s1"),
        describe_statement("s2"),
        bind_msg("p", "s1"),
        execute_msg("p", 0),
        bind_msg("p", "s2"),
        execute_msg("p", 0),
        sync_msg(),
    ] {
        buf.extend_from_slice(&msg.encode());
    }
    client.send_raw(&buf).await?;
    let msgs = client.read_until_ready_or_eof().await?;
    assert_exercised(&msgs, &client, "class-then-pass same portal");
    assert_no_canary(&client, "class-then-pass same portal");

    // Unnamed portal — the JDBC/psycopg reuse pattern.
    client = RawClient::connect(proxy.addr, DB).await?;
    buf.clear();
    for msg in [
        parse_msg("s1", "SELECT email, name FROM canary.subjects WHERE id = 1"),
        parse_msg("s2", "SELECT city, id FROM canary.subjects WHERE id = 1"),
        describe_statement("s1"),
        describe_statement("s2"),
        bind_msg("", "s1"),
        execute_msg("", 0),
        bind_msg("", "s2"),
        execute_msg("", 0),
        sync_msg(),
    ] {
        buf.extend_from_slice(&msg.encode());
    }
    client.send_raw(&buf).await?;
    let msgs = client.read_until_ready_or_eof().await?;
    assert_exercised(&msgs, &client, "class-then-pass unnamed portal");
    assert_no_canary(&client, "class-then-pass unnamed portal");

    // Binary Bind of the passthrough rebind.
    client = RawClient::connect(proxy.addr, DB).await?;
    buf.clear();
    for msg in [
        parse_msg("s1", "SELECT email, name FROM canary.subjects WHERE id = 1"),
        parse_msg("s2", "SELECT city, id FROM canary.subjects WHERE id = 1"),
        describe_statement("s1"),
        describe_statement("s2"),
        bind_msg("p", "s1"),
        execute_msg("p", 0),
        bind_msg_with_result_format("p", "s2", 1),
        execute_msg("p", 0),
        sync_msg(),
    ] {
        buf.extend_from_slice(&msg.encode());
    }
    client.send_raw(&buf).await?;
    let msgs = client.read_until_ready_or_eof().await?;
    assert_exercised(&msgs, &client, "class-then-pass binary Bind");
    assert_no_canary(&client, "class-then-pass binary Bind");

    // Control: two different portal names in one Sync still serve.
    client = RawClient::connect(proxy.addr, DB).await?;
    buf.clear();
    for msg in [
        parse_msg("s1", "SELECT email, name FROM canary.subjects WHERE id = 1"),
        parse_msg("s2", "SELECT city, id FROM canary.subjects WHERE id = 1"),
        describe_statement("s1"),
        describe_statement("s2"),
        bind_msg("p1", "s1"),
        execute_msg("p1", 0),
        bind_msg("p2", "s2"),
        execute_msg("p2", 0),
        sync_msg(),
    ] {
        buf.extend_from_slice(&msg.encode());
    }
    client.send_raw(&buf).await?;
    let msgs = client.read_until_ready_or_eof().await?;
    assert_served(&msgs, "different portal names same Sync");
    assert_no_canary(&client, "different portal names same Sync");

    // Pass-then-class on the same name: over-mask is fail-closed.
    client = RawClient::connect(proxy.addr, DB).await?;
    buf.clear();
    for msg in [
        parse_msg("s1", "SELECT city, id FROM canary.subjects WHERE id = 1"),
        parse_msg("s2", "SELECT email, name FROM canary.subjects WHERE id = 1"),
        describe_statement("s1"),
        describe_statement("s2"),
        bind_msg("p", "s1"),
        execute_msg("p", 0),
        bind_msg("p", "s2"),
        execute_msg("p", 0),
        sync_msg(),
    ] {
        buf.extend_from_slice(&msg.encode());
    }
    client.send_raw(&buf).await?;
    let msgs = client.read_until_ready_or_eof().await?;
    assert_exercised(&msgs, &client, "pass-then-class same portal");
    assert_no_canary(&client, "pass-then-class same portal");
    Ok(())
}

/// Close then Bind of the same portal must not leak the in-flight
/// Execute's rows.
///
/// Sibling of the 0.1.97 same-name rebind. `Close P p` dropped
/// `portal_bind_generations`, so `Bind p s_pass` started at generation 1
/// again and collided with the unfinished `PendingExecute`. In one Sync,
/// Execute runs before Describe is answered, so `pending.plan` is still
/// `None`. `streaming_plan` treated the rebound all-passthrough plan as
/// current; `Vetted::unmasked_row` released the canaries. No second
/// Execute required. Close S of the classified statement, unnamed
/// portal `""`, and binary Bind of the classified Execute leaked the
/// same way. Without Close the second Bind bumps to 2 and the proxy
/// refuses (existing 0.1.97 test).
///
/// Either a masked row or a `pgmask:` refusal is fail-closed. Cleartext
/// canaries are not.
#[tokio::test]
async fn close_then_rebind_same_portal_does_not_leak() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;

    // Close P then Bind passthrough, one Sync. No second Execute.
    let mut buf = Vec::new();
    for msg in [
        parse_msg("sc", "SELECT email, name FROM canary.subjects WHERE id = 1"),
        parse_msg("sp", "SELECT city, id FROM canary.subjects WHERE id = 1"),
        describe_statement("sc"),
        describe_statement("sp"),
        bind_msg("p", "sc"),
        execute_msg("p", 0),
        close_portal("p"),
        bind_msg("p", "sp"),
        sync_msg(),
    ] {
        buf.extend_from_slice(&msg.encode());
    }
    client.send_raw(&buf).await?;
    let msgs = client.read_until_ready_or_eof().await?;
    assert_exercised(&msgs, &client, "Close P then Bind same portal");
    assert_no_canary(&client, "Close P then Bind same portal");

    // Unnamed portal.
    client = RawClient::connect(proxy.addr, DB).await?;
    buf.clear();
    for msg in [
        parse_msg("sc", "SELECT email, name FROM canary.subjects WHERE id = 1"),
        parse_msg("sp", "SELECT city, id FROM canary.subjects WHERE id = 1"),
        describe_statement("sc"),
        describe_statement("sp"),
        bind_msg("", "sc"),
        execute_msg("", 0),
        close_portal(""),
        bind_msg("", "sp"),
        sync_msg(),
    ] {
        buf.extend_from_slice(&msg.encode());
    }
    client.send_raw(&buf).await?;
    let msgs = client.read_until_ready_or_eof().await?;
    assert_exercised(&msgs, &client, "Close P then Bind unnamed portal");
    assert_no_canary(&client, "Close P then Bind unnamed portal");

    // Close S of the classified statement implicitly closes its portals.
    client = RawClient::connect(proxy.addr, DB).await?;
    buf.clear();
    for msg in [
        parse_msg("sc", "SELECT email, name FROM canary.subjects WHERE id = 1"),
        parse_msg("sp", "SELECT city, id FROM canary.subjects WHERE id = 1"),
        describe_statement("sc"),
        describe_statement("sp"),
        bind_msg("p", "sc"),
        execute_msg("p", 0),
        close_statement("sc"),
        bind_msg("p", "sp"),
        sync_msg(),
    ] {
        buf.extend_from_slice(&msg.encode());
    }
    client.send_raw(&buf).await?;
    let msgs = client.read_until_ready_or_eof().await?;
    assert_exercised(&msgs, &client, "Close S then Bind same portal");
    assert_no_canary(&client, "Close S then Bind same portal");

    // Binary Bind of the classified Execute, then Close and text rebind.
    client = RawClient::connect(proxy.addr, DB).await?;
    buf.clear();
    for msg in [
        parse_msg("sc", "SELECT email, name FROM canary.subjects WHERE id = 1"),
        parse_msg("sp", "SELECT city, id FROM canary.subjects WHERE id = 1"),
        describe_statement("sc"),
        describe_statement("sp"),
        bind_msg_with_result_format("p", "sc", 1),
        execute_msg("p", 0),
        close_portal("p"),
        bind_msg("p", "sp"),
        sync_msg(),
    ] {
        buf.extend_from_slice(&msg.encode());
    }
    client.send_raw(&buf).await?;
    let msgs = client.read_until_ready_or_eof().await?;
    assert_exercised(
        &msgs,
        &client,
        "binary classified Execute then Close+rebind",
    );
    assert_no_canary(&client, "binary classified Execute then Close+rebind");
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
    assert_sql_cases(
        &mut client,
        &[
            SqlCase::refused("lower", "SELECT lower(email) FROM canary.subjects"),
            SqlCase::refused("concat", "SELECT email || '' FROM canary.subjects"),
            SqlCase::refused(
                "coalesce",
                "SELECT COALESCE(email, '') FROM canary.subjects",
            ),
            SqlCase::refused(
                "case",
                "SELECT CASE WHEN id > 0 THEN email END FROM canary.subjects",
            ),
            SqlCase::refused(
                "string_agg",
                "SELECT string_agg(email, ',') FROM canary.subjects",
            ),
            SqlCase::refused(
                "union",
                "SELECT email FROM canary.subjects UNION ALL \
                 SELECT email FROM canary.subjects",
            ),
            SqlCase::refused(
                "intersect",
                "SELECT email FROM canary.subjects INTERSECT \
                 SELECT email FROM canary.subjects",
            ),
            SqlCase::refused(
                "recursive CTE",
                "WITH RECURSIVE r(e) AS (SELECT email FROM canary.subjects WHERE id = 1 \
                 UNION ALL SELECT email FROM canary.subjects WHERE id = 2) SELECT e FROM r",
            ),
            SqlCase::refused(
                "scalar subquery",
                "SELECT (SELECT email FROM canary.subjects LIMIT 1)",
            ),
            SqlCase::refused("to_json", "SELECT to_json(s) FROM canary.subjects s"),
            SqlCase::refused(
                "row_to_json",
                "SELECT row_to_json(s) FROM canary.subjects s",
            ),
            SqlCase::refused("array_agg", "SELECT array_agg(email) FROM canary.subjects"),
        ],
    )
    .await?;
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
///
/// This loop is not a [`SqlCase`] matrix: `BEGIN` / `COMMIT` / reconnect-on-hang
/// shapes are not uniformly served or refused, and the canary property is the
/// connection-wide transcript. Per-query isolation belongs in the named
/// matrices above.
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

    assert_sql_cases(
        &mut client,
        &[
            // Classified through the parent: served, masked.
            SqlCase::served("partition parent star", "SELECT * FROM canary.events"),
            SqlCase::served("partition parent email", "SELECT email FROM canary.events"),
            // The partition by name is not in the catalog. Default-deny still
            // serves the row; the classified column comes back masked.
            SqlCase::served("named partition", "SELECT email FROM canary.events_2024"),
            // Inheritance, including the child's row through the parent.
            SqlCase::served("inheritance parent", "SELECT email FROM canary.people"),
            SqlCase::served(
                "inheritance ONLY parent",
                "SELECT email FROM ONLY canary.people",
            ),
            SqlCase::served("inheritance child", "SELECT email FROM canary.staff"),
            // A domain-typed column: masked like any other text column.
            SqlCase::served("domain column", "SELECT email FROM canary.contacts"),
            // A cast loses provenance, and that is refused — the general rule.
            SqlCase::refused("domain cast", "SELECT email::text FROM canary.contacts"),
            // A generated column is a second copy of a classified value under an
            // unclassified name. Default-deny is the only thing covering it.
            SqlCase::served("generated column", "SELECT email_copy FROM canary.derived"),
            SqlCase::served(
                "base and generated columns",
                "SELECT email, email_copy FROM canary.derived",
            ),
        ],
    )
    .await?;
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
        "DO $$ BEGIN RAISE EXCEPTION 'boom' USING SCHEMA = \
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

/// The type-aware unclassified fallback degrades to NULL instead of refusing.
///
/// The pre-type-aware default (`NULL` for everything) was total; the masks
/// that replaced it can fail per value. Each phase here is a shape that used
/// to work under blanket NULL and would refuse mid-stream if a fallback
/// failure were treated like a configured-mask failure:
///
/// 1. a `timestamptz` holding the ordinary sentinel `infinity`;
/// 2. a session that ran `SET datestyle TO 'German'` (allowed through the
///    read-only gate), so date output no longer parses as ISO;
/// 3. an unclassified `inet` column bound with binary result format, which
///    the text-only `ip-prefix` fallback cannot decode.
///
/// In every case the result set must be *served*, with the affected field
/// nulled and nothing sensitive crossing.
#[tokio::test]
async fn type_aware_fallback_degrades_to_null_instead_of_refusing() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    exec_direct(
        DB,
        "DROP TABLE IF EXISTS canary.netlog;
         CREATE TABLE canary.netlog (id int, ip inet, seen timestamptz, email text);
         INSERT INTO canary.netlog VALUES
           (1, '10.1.2.3', 'infinity', 'CANARY_EMAIL_a1b2c3'),
           (2, '10.1.2.4', '2077-06-15 10:00:00+00', 'CANARY_EMAIL_a1b2c3');",
    )
    .await?;
    let proxy = start_proxy(DB, Vec::new()).await?;

    // Phase 1: 'infinity' cannot be truncated to a year; the row must still be
    // served, with the field nulled rather than the stream refused.
    {
        let mut client = RawClient::connect(proxy.addr, DB).await?;
        let msgs = client
            .simple_query("SELECT ip, seen, email FROM canary.netlog ORDER BY id")
            .await?;
        assert_served(&msgs, "infinity timestamptz under the fallback");
        let text = client.received_text();
        assert!(
            !text.contains("pgmask:"),
            "a fallback-mask failure must not refuse the stream:\n{text}"
        );
        assert!(
            !text.contains("infinity"),
            "the undecodable value must be nulled, not passed through:\n{text}"
        );
        assert!(
            !text.contains("2077-06"),
            "the decodable row must still be coarsened to its year:\n{text}"
        );
        assert_no_canary(&client, "type-aware fallback, text formats");
    }

    // Phase 2: a client-chosen DateStyle makes every date rendering
    // undecodable. Served, nulled, no refusal.
    {
        let mut client = RawClient::connect(proxy.addr, DB).await?;
        client.simple_query("SET datestyle TO 'German'").await?;
        let msgs = client
            .simple_query("SELECT seen FROM canary.netlog WHERE id = 2")
            .await?;
        assert_served(&msgs, "German DateStyle under the fallback");
        let text = client.received_text();
        assert!(
            !text.contains("pgmask:"),
            "SET datestyle must not turn the fallback into a refusal:\n{text}"
        );
        assert!(
            !text.contains("2077"),
            "the non-ISO rendering must be nulled, not passed through:\n{text}"
        );
    }

    // Phase 3: Describe(Statement) reports text, so the fallback picks
    // ip-prefix; the Bind then flips the portal to binary, which ip-prefix
    // cannot decode. The rows must still be served, nulled.
    {
        let mut client = RawClient::connect(proxy.addr, DB).await?;
        client
            .send(parse_msg("s", "SELECT ip FROM canary.netlog ORDER BY id"))
            .await?;
        client.send(describe_statement("s")).await?;
        client
            .send(bind_msg_with_result_format("p", "s", 1))
            .await?;
        client.send(execute_msg("p", 0)).await?;
        client.send(sync_msg()).await?;
        let msgs = client.read_until_ready().await?;
        assert_served(&msgs, "binary-bound unclassified inet");
        let text = client.received_text();
        assert!(
            !text.contains("pgmask:"),
            "a Bind-time format flip must not refuse a fallback plan:\n{text}"
        );
        assert!(
            !text.contains("10.1.2"),
            "the packed value must be nulled, never decoded or passed:\n{text}"
        );
    }

    Ok(())
}

/// Catalog-resolved source nullability, including direct and nested domain
/// constraints, keeps automatic NULL fallbacks from contradicting a stored
/// column's declared contract. Nullable columns and domains retain the
/// availability-oriented fallback; the strict-NULL configuration is covered
/// separately by unit tests because it is an explicit operator choice.
#[tokio::test]
async fn type_aware_fallback_preserves_declared_not_null() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    exec_direct(
        DB,
        "DROP TABLE IF EXISTS canary.nullability;
         DROP DOMAIN IF EXISTS canary.required_bigint;
         CREATE DOMAIN canary.required_bigint AS bigint NOT NULL;
         CREATE DOMAIN canary.nested_required_bigint AS canary.required_bigint;
         CREATE DOMAIN canary.optional_bigint AS bigint;
         CREATE TABLE canary.nullability (
           required bigint NOT NULL,
           domain_required canary.required_bigint,
           nested_domain_required canary.nested_required_bigint,
           domain_optional canary.optional_bigint,
           optional bigint
         );
         INSERT INTO canary.nullability VALUES (42, 42, 42, 42, 42);",
    )
    .await?;
    let proxy = start_proxy(DB, Vec::new()).await?;

    let mut required = RawClient::connect(proxy.addr, DB).await?;
    let msgs = required
        .simple_query("SELECT required FROM canary.nullability")
        .await?;
    assert!(
        !msgs.iter().any(|message| message.tag == b'T'),
        "the incompatible result must be refused before RowDescription"
    );
    assert_refused(&required, "automatic NULL for NOT NULL bigint");
    assert!(
        required.received_text().contains("NOT NULL"),
        "the refusal should explain the source contract"
    );

    let mut domain_required = RawClient::connect(proxy.addr, DB).await?;
    let msgs = domain_required
        .simple_query("SELECT domain_required FROM canary.nullability")
        .await?;
    assert!(
        !msgs.iter().any(|message| message.tag == b'T'),
        "a domain's NOT NULL constraint must be enforced before RowDescription"
    );
    assert_refused(
        &domain_required,
        "automatic NULL for domain-constrained bigint",
    );

    let mut nested_domain_required = RawClient::connect(proxy.addr, DB).await?;
    let msgs = nested_domain_required
        .simple_query("SELECT nested_domain_required FROM canary.nullability")
        .await?;
    assert!(
        !msgs.iter().any(|message| message.tag == b'T'),
        "an inherited domain NOT NULL constraint must be enforced before RowDescription"
    );
    assert_refused(
        &nested_domain_required,
        "automatic NULL for nested domain-constrained bigint",
    );

    let mut domain_optional = RawClient::connect(proxy.addr, DB).await?;
    let msgs = domain_optional
        .simple_query("SELECT domain_optional FROM canary.nullability")
        .await?;
    assert_served(&msgs, "automatic NULL for a nullable domain");
    assert!(
        !domain_optional.received_text().contains("pgmask:"),
        "a nullable domain should retain the automatic NULL fallback"
    );

    let mut optional = RawClient::connect(proxy.addr, DB).await?;
    let msgs = optional
        .simple_query("SELECT optional FROM canary.nullability")
        .await?;
    assert_served(&msgs, "automatic NULL for nullable bigint");
    assert!(
        !optional.received_text().contains("pgmask:"),
        "a nullable source should retain the automatic NULL fallback"
    );
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

/// `lineage = "allow"` releases an expression whose resolved sources are all
/// passthrough. That inverts the default, so a name the resolver never reports
/// has to be a name the backstop still sees — including encodings the token
/// stream does not spell as the catalog word.
///
/// Measured through the shipped GUI catalog: concatenating released `city`
/// with `u&"email"` inside a scalar subquery returned the address in the
/// clear (`Denveruser1@example.com`). `sqllineage` does not enter the
/// subquery; the lexer used to skip the `UIDENT`. Same hole for `CONCAT`
/// and `ARRAY`. Bare `SELECT u&"email"` was already masked (OID provenance).
#[tokio::test]
async fn lineage_does_not_release_a_unicode_escaped_masked_name() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy_allowing_lineage(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;

    // Control: lineage still releases an expression over only passthrough
    // columns. If this is refused, the leak queries below prove nothing —
    // they would be refused because lineage is off, not because the backstop
    // named `email`.
    let msgs = client
        .simple_query("SELECT upper(city) FROM canary.subjects")
        .await?;
    assert_served(&msgs, "lineage still releases a passthrough expression");
    assert!(
        client.received_text().contains("PORTLAND"),
        "city is mask = none: {}",
        client.received_text()
    );
    assert_no_canary(&client, "passthrough expression under lineage");

    // Guard 7: a SubLink in the output is incomplete sources even when every
    // named column is released. Guard 6 does not fire here (`city` is
    // `mask = "none"`). The unicode cases below would still be refused if
    // this were missing; this is the pin that it is not.
    {
        let sql = "SELECT city || (SELECT city FROM canary.subjects LIMIT 1) \
                   FROM canary.subjects";
        let mut client = RawClient::connect(proxy.addr, DB).await?;
        let msgs = client.simple_query(sql).await?;
        assert_exercised(&msgs, &client, sql);
        assert_refused(&client, sql);
        assert_no_canary(&client, sql);
    }
    // A subquery in WHERE is a predicate, not a source of the field.
    {
        let sql = "SELECT upper(city) FROM canary.subjects \
                   WHERE city IN (SELECT city FROM canary.subjects)";
        let mut client = RawClient::connect(proxy.addr, DB).await?;
        let msgs = client.simple_query(sql).await?;
        assert_served(&msgs, sql);
        assert!(
            client.received_text().contains("PORTLAND"),
            "{sql}: {}",
            client.received_text()
        );
        assert_no_canary(&client, sql);
    }
    // Following a FROM alias of a released column is still closed.
    {
        let sql = "SELECT upper(x) FROM (SELECT city AS x FROM canary.subjects) q";
        let mut client = RawClient::connect(proxy.addr, DB).await?;
        let msgs = client.simple_query(sql).await?;
        assert_served(&msgs, sql);
        assert!(
            client.received_text().contains("PORTLAND"),
            "{sql}: {}",
            client.received_text()
        );
        assert_no_canary(&client, sql);
    }
    // A FROM colnames list remaps attnums by position. `city` here is
    // email (attnum 2); Guard 6 never sees the word `email`. Must refuse
    // and never contain the canary. A SELECT-list `AS` is not this list.
    for sql in [
        "SELECT upper(city) FROM canary.subjects AS t(id, city, n, note, c) \
         WHERE id = 1",
        "SELECT city || 'x' FROM canary.subjects AS t(id, city, n, note, c) \
         WHERE id = 1",
        "SELECT city FROM canary.subjects AS t(id, city, n, note, c) \
         WHERE id = 1 UNION ALL SELECT city FROM canary.subjects \
         WHERE id = 1",
        "SELECT upper(city) FROM canary.subject_view AS v(id, city, n, c) \
         WHERE id = 1",
    ] {
        let mut client = RawClient::connect(proxy.addr, DB).await?;
        let msgs = client.simple_query(sql).await?;
        assert_exercised(&msgs, &client, sql);
        assert_refused(&client, sql);
        assert_no_canary(&client, sql);
    }
    // The wrap that reopened the SubLink leak: outer field is ColumnRef
    // `x`, Guard 6 never sees `email` because the FROM alias list renamed
    // it, and sqllineage still reports only `city`.
    for sql in [
        "SELECT x FROM (SELECT city || (SELECT a FROM canary.subjects \
            AS t(id, a, n, note, city) LIMIT 1) AS x FROM canary.subjects \
            WHERE id = 1) q",
        "SELECT q.x FROM (SELECT city || (SELECT a FROM canary.subjects \
            AS t(id, a, n, note, city) LIMIT 1) AS x FROM canary.subjects \
            WHERE id = 1) q",
        "WITH q AS (SELECT city || (SELECT a FROM canary.subjects \
            AS t(id, a, n, note, city) LIMIT 1) AS x FROM canary.subjects \
            WHERE id = 1) SELECT x FROM q",
        "SELECT x FROM (SELECT CONCAT(city, (SELECT a FROM canary.subjects \
            AS t(id, a, n, note, city) LIMIT 1)) AS x FROM canary.subjects \
            WHERE id = 1) q",
        "SELECT x FROM (SELECT city || (SELECT city FROM canary.subjects \
            LIMIT 1) AS x FROM canary.subjects) q",
    ] {
        let mut client = RawClient::connect(proxy.addr, DB).await?;
        let msgs = client.simple_query(sql).await?;
        assert_exercised(&msgs, &client, sql);
        assert_refused(&client, sql);
        assert_no_canary(&client, sql);
    }

    for sql in [
        r#"SELECT city || (SELECT u&"email" FROM canary.subjects c2
            WHERE c2.id = canary.subjects.id LIMIT 1)
           FROM canary.subjects WHERE id = 1"#,
        r#"SELECT city || (SELECT u&"e\006dail" FROM canary.subjects LIMIT 1)
           FROM canary.subjects"#,
        r#"SELECT CONCAT(city, (SELECT u&"email" FROM canary.subjects LIMIT 1))
           FROM canary.subjects"#,
        r#"SELECT ARRAY[city, (SELECT u&"email" FROM canary.subjects LIMIT 1)]
           FROM canary.subjects"#,
    ] {
        // A fresh client so a refusal on an earlier spelling cannot satisfy
        // `assert_refused` for a later one that started leaking.
        let mut client = RawClient::connect(proxy.addr, DB).await?;
        let msgs = client.simple_query(sql).await?;
        assert_exercised(&msgs, &client, sql);
        assert_refused(&client, sql);
        assert_no_canary(&client, sql);
    }
    Ok(())
}

// --- The rescue path --------------------------------------------------------
//
// analysis turns refusals into passthroughs for expressions positively
// identified as carrying no column value. That direction is the dangerous one:
// a wrong rule here is a leak, not a false pass. These tests exist to make sure
// nothing can ride through it.

#[tokio::test]
async fn provably_column_free_expressions_are_served() -> Result<()> {
    require_pg!();
    load_schema(DB).await?;
    let proxy = start_proxy(DB, default_rules()).await?;
    let mut client = RawClient::connect(proxy.addr, DB).await?;

    assert_sql_cases(
        &mut client,
        &[
            SqlCase::served("integer literal", "SELECT 1"),
            SqlCase::served("now()", "SELECT now()"),
            SqlCase::served("current_database()", "SELECT current_database()"),
            SqlCase::served("count(*)", "SELECT count(*) FROM canary.subjects"),
            SqlCase::served(
                "count grouped by released column",
                "SELECT city, count(*) FROM canary.subjects GROUP BY city",
            ),
        ],
    )
    .await?;
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
    assert_sql_cases(
        &mut client,
        &[
            SqlCase::exercised("max", "SELECT max(email) FROM canary.subjects"),
            SqlCase::exercised("min", "SELECT min(email) FROM canary.subjects"),
            SqlCase::exercised(
                "string_agg",
                "SELECT string_agg(email, ',') FROM canary.subjects",
            ),
            SqlCase::exercised("array_agg", "SELECT array_agg(email) FROM canary.subjects"),
            SqlCase::exercised("json_agg", "SELECT json_agg(email) FROM canary.subjects"),
            SqlCase::exercised(
                "first_value",
                "SELECT first_value(email) OVER (ORDER BY id) FROM canary.subjects",
            ),
            SqlCase::exercised(
                "last_value",
                "SELECT last_value(email) OVER (ORDER BY id) FROM canary.subjects",
            ),
            SqlCase::exercised(
                "lag",
                "SELECT lag(email) OVER (ORDER BY id) FROM canary.subjects",
            ),
            SqlCase::exercised(
                "nth_value",
                "SELECT nth_value(email, 1) OVER (ORDER BY id) FROM canary.subjects",
            ),
            SqlCase::exercised(
                "mode",
                "SELECT mode() WITHIN GROUP (ORDER BY email) FROM canary.subjects",
            ),
            SqlCase::exercised(
                "scalar subquery",
                "SELECT (SELECT email FROM canary.subjects LIMIT 1)",
            ),
            SqlCase::exercised(
                "coalesce",
                "SELECT coalesce(email, '') FROM canary.subjects",
            ),
            SqlCase::exercised(
                "literal beside classified column",
                "SELECT 1, email FROM canary.subjects",
            ),
            SqlCase::exercised("literal union", "SELECT 1 UNION ALL SELECT 1"),
        ],
    )
    .await?;
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
    assert_sql_cases(
        &mut client,
        &[
            SqlCase::exercised("star then literal", "SELECT *, 1 FROM canary.subjects"),
            SqlCase::exercised("literal then star", "SELECT 1, * FROM canary.subjects"),
            SqlCase::exercised(
                "qualified star with window",
                "SELECT s.*, count(*) OVER () FROM canary.subjects s",
            ),
        ],
    )
    .await?;
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

    assert_sql_cases(
        &mut client,
        &[
            SqlCase::served("count", "SELECT count(email) FROM canary.subjects"),
            SqlCase::served(
                "count distinct",
                "SELECT count(DISTINCT email) FROM canary.subjects",
            ),
            SqlCase::served(
                "count grouped by city",
                "SELECT city, count(*) FROM canary.subjects GROUP BY city",
            ),
            SqlCase::served(
                "count filter",
                "SELECT count(*) FILTER (WHERE email = 'CANARY_EMAIL_a1b2c3') \
                 FROM canary.subjects",
            ),
            SqlCase::served(
                "row_number over classified order",
                "SELECT row_number() OVER (ORDER BY email) FROM canary.subjects",
            ),
            SqlCase::served(
                "rank over classified order",
                "SELECT rank() OVER (ORDER BY name) FROM canary.subjects",
            ),
        ],
    )
    .await?;

    // A boolean reduction is the identity over one row. Before the summary
    // partition was tightened, this returned `true` through a column whose
    // direct projection is null-masked.
    let sql = "SELECT bool_or(secret_flag) FROM canary.no_unique WHERE salary = 987654321";
    let msgs = client.simple_query(sql).await?;
    let row = msgs
        .iter()
        .find(|m| m.tag == b'D')
        .expect("the boolean summary should be served and masked");
    assert_eq!(
        pgmask::protocol::parse_data_row(&row.body)?,
        vec![None],
        "a singleton boolean aggregate must inherit the source's null mask"
    );
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
    // Default-deny masks the reshaped column and still serves the row —
    // the guarantee is that the value never appears, not that the query is
    // refused.
    assert_served(&msgs, "reshape: immediately after ALTER");
    assert_no_canary(&after, "reshape: immediately after ALTER");

    exec_direct(DB, "DROP TABLE IF EXISTS canary.reshape").await?;
    Ok(())
}
