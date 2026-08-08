//! Cross-check our wire decoder against an independent implementation.
//!
//! `crates/proxy/src/protocol.rs` is hand-written, and the case for that is in
//! its module docs: a proxy must forward message types it does not understand
//! byte-for-byte, and a library that models the protocol as a closed enum turns
//! an unknown tag into an error. `pgwire` does exactly that —
//! `_ => Err(PgWireError::InvalidMessageType(first_byte))` — and does not model
//! `FunctionCallResponse` at all, which is one of the two messages we
//! deliberately refuse. So it cannot replace our decoder.
//!
//! It can do something more useful: be a second opinion. `RowDescription` is
//! where the entire security model lives — the table OID and attnum in it decide
//! whether a field is masked, released or refused — and it is parsed by hand
//! from a byte buffer. Having a second implementation read the same bytes and
//! agree is cheap, and a disagreement is a bug in one of us.
//!
//! Scope is deliberately narrow. pgwire keeps `DataRow` as an undecoded
//! `BytesMut` plus a field count, so comparing column *values* would mean
//! parsing their buffer with our own logic and proving nothing. The column count
//! is compared, because that they do decode.

use bytes::{BufMut, Bytes, BytesMut};
use pgmask::protocol;
use pgwire::messages::{DecodeContext, PgWireBackendMessage};

/// pgwire's default context is mid-handshake and would read these as startup
/// packets. This is a connection that is past that.
fn established() -> DecodeContext {
    // `DecodeContext` is #[non_exhaustive], so it is built and then adjusted.
    let mut ctx = DecodeContext::default();
    ctx.awaiting_frontend_ssl = false;
    ctx.awaiting_frontend_startup = false;
    ctx
}

fn framed(tag: u8, body: &Bytes) -> BytesMut {
    let mut frame = BytesMut::new();
    frame.put_u8(tag);
    frame.put_i32((body.len() + 4) as i32);
    frame.put_slice(body);
    frame
}

fn decode_with_pgwire(tag: u8, body: &Bytes) -> PgWireBackendMessage {
    let mut buf = framed(tag, body);
    PgWireBackendMessage::decode(&mut buf, &established())
        .expect("pgwire decodes")
        .expect("a whole message")
}

/// name, table OID, attnum, type OID, format code.
type Field<'a> = (&'a str, u32, i16, u32, i16);

/// A `RowDescription` body built the way a server builds one, so neither
/// decoder is reading bytes it produced.
fn row_description_body(fields: &[Field<'_>]) -> Bytes {
    let mut body = BytesMut::new();
    body.put_i16(fields.len() as i16);
    for (name, table_oid, column_id, type_oid, format) in fields {
        body.put_slice(name.as_bytes());
        body.put_u8(0);
        body.put_u32(*table_oid);
        body.put_i16(*column_id);
        body.put_u32(*type_oid);
        body.put_i16(-1); // type size
        body.put_i32(-1); // type modifier
        body.put_i16(*format);
    }
    body.freeze()
}

#[test]
fn provenance_fields_agree_with_an_independent_decoder() {
    let cases: &[&[Field<'_>]] = &[
        &[("email", 16_384, 2, 25, 0)],
        // An expression: both must read zeroes, which is what makes us refuse it.
        &[("count", 0, 0, 20, 0)],
        &[
            ("id", 16_384, 1, 23, 1), // binary format
            ("email", 16_384, 2, 25, 0),
            ("total", 0, 0, 1700, 0),
        ],
        // Extremes, where a signedness or width mistake would show up.
        &[("weird name with spaces", 4_294_967_295, i16::MAX, 25, 0)],
        &[("neg", 1, -2, 26, 0)], // system column: attnum is negative
        &[],                      // zero fields is legal
    ];

    for fields in cases {
        let body = row_description_body(fields);
        let ours = protocol::parse_row_description(&body).expect("ours decodes");

        let PgWireBackendMessage::RowDescription(theirs) = decode_with_pgwire(b'T', &body) else {
            panic!("pgwire disagreed about the message type");
        };

        assert_eq!(ours.len(), theirs.fields.len(), "field count");
        for (i, (ours, theirs)) in ours.iter().zip(&theirs.fields).enumerate() {
            assert_eq!(ours.name, theirs.name, "field {i} name");
            assert_eq!(
                ours.table_oid, theirs.table_id as u32,
                "field {i} table oid — this decides masking"
            );
            assert_eq!(
                ours.column_id, theirs.column_id,
                "field {i} attnum — this decides masking"
            );
            assert_eq!(ours.type_oid, theirs.type_id, "field {i} type oid");
            assert_eq!(ours.format, theirs.format_code, "field {i} format");
        }
    }
}

#[test]
fn data_row_column_counts_agree_with_an_independent_decoder() {
    // pgwire leaves the values undecoded, so the count is the only claim it
    // makes here — but a count mismatch would desynchronise masking against
    // the plan, which is the failure that matters.
    let cases: &[&[Option<&[u8]>]] = &[
        &[Some(b"user@example.com")],
        &[None],      // SQL NULL
        &[Some(b"")], // empty, which is not NULL
        &[Some(b"a"), None, Some(b"")],
        &[Some(&[0xff, 0x00, 0xfe])], // non-UTF8 binary
        &[],
    ];

    for values in cases {
        let mut body = BytesMut::new();
        body.put_i16(values.len() as i16);
        for value in *values {
            match value {
                Some(bytes) => {
                    body.put_i32(bytes.len() as i32);
                    body.put_slice(bytes);
                }
                None => body.put_i32(-1),
            }
        }
        let body = body.freeze();

        let ours = protocol::parse_data_row(&body).expect("ours decodes");
        let PgWireBackendMessage::DataRow(theirs) = decode_with_pgwire(b'D', &body) else {
            panic!("pgwire disagreed about the message type");
        };

        assert_eq!(ours.len(), theirs.field_count as usize, "column count");
        // ...and our own reading of NULL-vs-empty, which pgwire cannot check.
        let expected: Vec<Option<&[u8]>> = values.to_vec();
        let got: Vec<Option<&[u8]>> = ours.iter().map(|v| v.as_deref()).collect();
        assert_eq!(got, expected, "values");
    }
}

#[test]
fn a_row_we_build_is_read_back_the_same_by_an_independent_decoder() {
    // The masking path rebuilds DataRow bodies. Handing one to a decoder that
    // never saw our encoder is the check that we build them the way a server
    // does, not merely the way we read them.
    let values = vec![
        Some(Bytes::from_static(b"***")),
        None,
        Some(Bytes::from_static(b"1970-01-01")),
    ];
    let message = protocol::build_data_row(&values);
    let encoded = message.encode();

    let mut buf = BytesMut::from(&encoded[..]);
    let decoded = PgWireBackendMessage::decode(&mut buf, &established())
        .expect("pgwire reads what we built")
        .expect("a whole message");
    let PgWireBackendMessage::DataRow(theirs) = decoded else {
        panic!("we built something that is not a DataRow");
    };
    assert_eq!(theirs.field_count as usize, values.len());
    assert!(
        buf.is_empty(),
        "we wrote a length that does not match the body"
    );
}

#[test]
fn pgwire_cannot_do_the_job_our_decoder_exists_for() {
    // Documents why this is a dev-dependency and not a dependency. If pgwire
    // ever grows a pass-through variant, this test fails and the decision is
    // worth revisiting — which is the point of asserting it rather than only
    // writing it down.
    let body = Bytes::new();
    let frame = framed(b'V', &body); // FunctionCallResponse: a real message

    // Ours carries it as opaque bytes, which is what lets the proxy refuse it
    // deliberately instead of dying on it.
    let ours = protocol::Message::new(b'V', body);
    assert_eq!(ours.encode(), frame, "must round-trip byte-for-byte");

    let mut buf = frame.clone();
    assert!(
        PgWireBackendMessage::decode(&mut buf, &established()).is_err(),
        "pgwire grew support for unknown tags — reconsider the dependency"
    );
}
