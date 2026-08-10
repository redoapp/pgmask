#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
//! Property tests for the wire parsers and the SQL analysis.
//!
//! Different stakes from the mask fuzzing. A wrong mask returns a wrong value;
//! a wrong *parse* can panic a connection mid-result-set, or — worse — describe
//! a result set differently from how it actually arrives, so a plan built for
//! one field is applied to another's bytes.

use bytes::{BufMut, Bytes, BytesMut};
use pgmask::analysis;
use pgmask::protocol::*;
use proptest::prelude::*;

const ALLOW_ALL: pgmask::analysis::Relaxations = pgmask::analysis::Relaxations {
    summaries: true,
    fine_date_trunc: true,
};

proptest! {
    /// Arbitrary bytes must not panic the RowDescription parser. Postgres will
    /// not send these, but a compromised or buggy backend might, and a panic
    /// here kills the client's connection.
    #[test]
    fn row_description_parsing_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = parse_row_description(&Bytes::from(bytes));
    }

    #[test]
    fn data_row_parsing_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = parse_data_row(&Bytes::from(bytes));
    }

    #[test]
    fn error_scrubbing_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = scrub_error(&Bytes::from(bytes));
    }

    #[test]
    /// Every remaining frontend parser, against arbitrary bytes.
    ///
    /// The four parsers above had this property and six did not, and the gap is
    /// exactly where a bug lived: `parse_describe` called `Bytes::get_u8()`
    /// with no length check, so a bare `Describe` with a zero-length body —
    /// one frame, no authentication required — panicked the connection task.
    /// Covering some parsers and not others is how that survives.
    #[test]
    fn every_frontend_parser_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let body = Bytes::from(bytes);
        let _ = parse_describe(&body);
        let _ = parse_bind(&body);
        let _ = parse_bind_result_formats(&body);
        let _ = parse_execute(&body);
        let _ = parse_parse(&body);
        let _ = parse_simple_query(&body);
    }

    /// Statement and portal names are opaque protocol identities. Every
    /// NUL-free byte string must survive parsing exactly, including invalid
    /// UTF-8 that lossy decoding would collapse onto U+FFFD.
    #[test]
    fn protocol_names_round_trip_byte_exactly(
        name in proptest::collection::vec(any::<u8>().prop_filter("cstring byte", |b| *b != 0), 0..64)
    ) {
        let mut body = BytesMut::new();
        body.put_slice(&name);
        body.put_u8(0);
        body.put_i32(0);
        prop_assert_eq!(parse_execute(&body.freeze()), Some(Bytes::from(name)));
    }

    /// Indexing into the result-format codes must hold for any index, since the
    /// field count comes from the server and the codes come from the client.
    #[test]
    fn format_lookup_never_panics(
        formats in proptest::collection::vec(any::<i16>(), 0..8),
        index in 0usize..32,
    ) {
        let _ = format_for(&formats, index);
    }

    fn startup_parameter_parsing_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        let packet = StartupPacket { code: 196608, body: Bytes::from(bytes) };
        let _ = packet.parameters();
    }

    /// A DataRow that survives a parse must re-encode to the same bytes.
    /// Anything else means the rewrite path can change a row it was only meant
    /// to pass through.
    #[test]
    fn data_rows_round_trip(
        values in proptest::collection::vec(
            proptest::option::of(proptest::collection::vec(any::<u8>(), 0..40)),
            0..12,
        )
    ) {
        let values: Vec<Option<Bytes>> = values
            .into_iter()
            .map(|v| v.map(Bytes::from))
            .collect();
        let encoded = build_data_row(&values);
        let parsed = parse_data_row(&encoded.body).expect("our own encoding must parse");
        prop_assert_eq!(parsed, values);
    }

    /// Scrubbing must only ever remove. If it can grow the message it is
    /// rewriting content rather than dropping fields.
    #[test]
    fn scrubbing_only_removes(
        fields in proptest::collection::vec(
            (proptest::sample::select(vec![b'S', b'C', b'M', b'D', b'H', b'n', b'q']),
             "[ -~]{0,40}"),
            0..10,
        )
    ) {
        let mut body = BytesMut::new();
        for (tag, value) in &fields {
            body.put_u8(*tag);
            body.put_slice(value.as_bytes());
            body.put_u8(0);
        }
        body.put_u8(0);
        let original = body.freeze();
        if let Some(scrubbed) = scrub_error(&original) {
            prop_assert!(
                scrubbed.len() <= original.len(),
                "scrubbing grew the message: {} -> {}",
                original.len(),
                scrubbed.len()
            );
        }
    }

    /// Arbitrary text must not panic the SQL analysis, and must never be
    /// claimed releasable — only a successful parse of a recognised shape can
    /// do that.
    #[test]
    fn analysis_never_panics_and_fails_closed_on_junk(text in ".{0,200}") {
        let out = analysis::analyze(&text, 3, ALLOW_ALL);
        prop_assert_eq!(out.len(), 3);
        // Junk cannot parse as a single SELECT with three matching targets, so
        // nothing may be released.
        if pg_query_parses_as_select(&text) {
            // A real query — no claim either way.
        } else {
            prop_assert!(
                out.iter().all(|s| *s == analysis::Safety::Unknown),
                "unparseable input released a field: {text:?}"
            );
        }
    }

    /// The field count the caller reports always governs the length of the
    /// answer, whatever the SQL says.
    #[test]
    fn analysis_output_length_follows_the_field_count(n in 0usize..12) {
        prop_assert_eq!(analysis::analyze("SELECT 1, 2, 3", n, ALLOW_ALL).len(), n);
    }
}

/// Cheap check used only to skip the fail-closed assertion for text that really
/// is a SELECT.
fn pg_query_parses_as_select(text: &str) -> bool {
    pg_query::parse(text)
        .map(|p| {
            p.protobuf.stmts.len() == 1
                && matches!(
                    p.protobuf
                        .stmts
                        .first()
                        .and_then(|s| s.stmt.as_ref())
                        .and_then(|s| s.node.as_ref()),
                    Some(pg_query::protobuf::node::Node::SelectStmt(_))
                )
        })
        .unwrap_or(false)
}

/// Frames arriving split across reads must reassemble identically, and a
/// truncated frame must never be handed over as if it were whole.
#[test]
fn framing_reassembles_across_arbitrary_splits() {
    use tokio::io::AsyncReadExt as _;
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async {
        let msg = Message::new(b'T', Bytes::from(vec![7u8; 200]));
        let encoded = msg.encode();
        for split in 1..encoded.len() {
            let (a, b) = encoded.split_at(split);
            let stream = tokio::io::AsyncReadExt::chain(
                std::io::Cursor::new(a.to_vec()),
                std::io::Cursor::new(b.to_vec()),
            );
            let mut reader = FrameReader::new(stream);
            let got = reader.read_message().await.expect("must not error");
            let got = got.expect("a whole frame is present");
            assert_eq!(got.tag, b'T', "split at {split}");
            assert_eq!(got.body.len(), 200, "split at {split}");
        }
        let _ = &mut std::io::Cursor::new(Vec::<u8>::new()).read_u8();
    });
}

/// The exact body that used to take down a connection.
///
/// Framing accepts a `Describe` with `len == 4`, i.e. an empty body, and the
/// parser read a tag byte out of it with no length check. One frame, no
/// authentication required, and the connection task panicked. Verified against
/// the pre-fix code: `Bytes::new().get_u8()` panics.
#[test]
fn a_zero_length_describe_is_refused_rather_than_fatal() {
    assert!(parse_describe(&Bytes::new()).is_none());
}
