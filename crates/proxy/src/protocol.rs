//! Postgres wire protocol: just enough of it.
//!
//! We deliberately do **not** model the protocol fully. A masking proxy needs to
//! understand exactly four things — `RowDescription` (provenance), `DataRow`
//! (the bytes to rewrite), `ErrorResponse` (scrubbing), and a handful of
//! frontend messages that steer the state machine. Everything else is framed and
//! forwarded byte-for-byte.
//!
//! That is a security property, not laziness: bytes we never interpret are bytes
//! we cannot misinterpret. The framing layer is the only thing that must be
//! exhaustively correct, and framing is simple — after startup every message is
//! `[tag: u8][len: i32 including itself][body]`.

use anyhow::{bail, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

// Backend (server -> client) message tags we act on.
pub const B_AUTHENTICATION: u8 = b'R';
pub const B_ROW_DESCRIPTION: u8 = b'T';
pub const B_DATA_ROW: u8 = b'D';
pub const B_COPY_OUT_RESPONSE: u8 = b'H';
pub const B_COPY_BOTH_RESPONSE: u8 = b'W';
pub const B_ERROR_RESPONSE: u8 = b'E';
pub const B_NOTICE_RESPONSE: u8 = b'N';
pub const B_READY_FOR_QUERY: u8 = b'Z';
pub const B_COPY_DATA: u8 = b'd';
pub const B_COPY_DONE: u8 = b'c';

/// Backend messages that carry no row data and are safe to forward verbatim.
///
/// This is an allowlist on purpose. The backend direction has no catch-all,
/// because an unrecognised message may carry data and "forward it, we do not
/// know what it is" is the opposite of fail-closed. Anything absent here is
/// refused and the connection closed.
pub const BACKEND_CONTROL_TAGS: &[u8] = &[
    b'R', // Authentication*
    b'K', // BackendKeyData
    b'S', // ParameterStatus
    b'Z', // ReadyForQuery
    b'C', // CommandComplete
    b'I', // EmptyQueryResponse
    b'A', // NotificationResponse (payload is application text, not table data)
    b'1', // ParseComplete
    b'2', // BindComplete
    b'3', // CloseComplete
    b's', // PortalSuspended
    b't', // ParameterDescription
    b'G', // CopyInResponse — a write path, nothing flows outward
    b'v', // NegotiateProtocolVersion
];

// Frontend (client -> server) message tags we act on.
pub const F_QUERY: u8 = b'Q';
pub const F_BIND: u8 = b'B';
pub const F_DESCRIBE: u8 = b'D';
pub const F_EXECUTE: u8 = b'E';
pub const F_FUNCTION_CALL: u8 = b'F';
pub const F_TERMINATE: u8 = b'X';

/// Type OIDs whose binary representation is byte-identical to their text
/// representation, so masking is format-agnostic for them.
pub const TEXT_FAMILY_OIDS: &[u32] = &[
    25,   // text
    1043, // varchar
    1042, // bpchar
    19,   // name
    705,  // unknown
];

pub fn is_text_family(oid: u32) -> bool {
    TEXT_FAMILY_OIDS.contains(&oid)
}

/// A framed protocol message.
///
/// `body` is a zero-copy slice of `raw`, so forwarding an untouched message is a
/// refcount bump rather than a re-encode. On a bulk result set the overwhelming
/// majority of messages are forwarded verbatim, and that path should cost
/// nothing.
#[derive(Debug, Clone)]
pub struct Message {
    pub tag: u8,
    pub body: Bytes,
    raw: Bytes,
}

impl Message {
    /// Build a message from a tag and body, encoding the frame once.
    pub fn new(tag: u8, body: Bytes) -> Self {
        let mut raw = BytesMut::with_capacity(body.len() + 5);
        raw.put_u8(tag);
        raw.put_i32(body.len() as i32 + 4);
        raw.put_slice(&body);
        let raw = raw.freeze();
        let body = raw.slice(5..);
        Self { tag, body, raw }
    }

    /// Wrap a complete frame already read off the wire.
    fn from_frame(raw: Bytes) -> Self {
        let tag = raw[0];
        let body = raw.slice(5..);
        Self { tag, body, raw }
    }

    /// The frame as it goes on the wire. Cheap — no copy.
    pub fn encode(&self) -> Bytes {
        self.raw.clone()
    }
}

/// The first packet(s) of a connection carry no tag, only a length.
#[derive(Debug, Clone)]
pub struct StartupPacket {
    pub code: i32,
    pub body: Bytes,
}

pub const SSL_REQUEST_CODE: i32 = 80877103;
pub const GSSENC_REQUEST_CODE: i32 = 80877104;
pub const CANCEL_REQUEST_CODE: i32 = 80877102;

impl StartupPacket {
    pub fn encode(&self) -> Bytes {
        let mut out = BytesMut::with_capacity(self.body.len() + 8);
        out.put_i32(self.body.len() as i32 + 8);
        out.put_i32(self.code);
        out.put_slice(&self.body);
        out.freeze()
    }

    /// Parse the null-terminated key/value pairs of a StartupMessage body.
    pub fn parameters(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let mut buf = self.body.clone();
        while let Some(key) = read_cstring(&mut buf) {
            if key.is_empty() {
                break;
            }
            let Some(val) = read_cstring(&mut buf) else {
                break;
            };
            out.push((key, val));
        }
        out
    }
}

/// Cancel-safe framed reader.
///
/// `read_buf` only ever appends, and `try_*` only consumes whole frames, so
/// dropping the future mid-frame (which `tokio::select!` does constantly) cannot
/// lose bytes.
pub struct FrameReader<R> {
    inner: R,
    buf: BytesMut,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buf: BytesMut::with_capacity(16 * 1024),
        }
    }

    /// Read one tagged message. `Ok(None)` on clean EOF.
    pub async fn read_message(&mut self) -> Result<Option<Message>> {
        loop {
            if let Some(msg) = try_take_message(&mut self.buf)? {
                return Ok(Some(msg));
            }
            if self.inner.read_buf(&mut self.buf).await? == 0 {
                if self.buf.is_empty() {
                    return Ok(None);
                }
                bail!(
                    "peer closed mid-message ({} bytes buffered)",
                    self.buf.len()
                );
            }
        }
    }

    /// Take an already-buffered message without touching the socket.
    ///
    /// One `read_buf` typically yields many messages on a bulk result set.
    /// Draining them before flushing turns one syscall per row into one syscall
    /// per kernel buffer, which is the difference between ~4us and ~0.2us a row.
    pub fn try_buffered_message(&mut self) -> Result<Option<Message>> {
        try_take_message(&mut self.buf)
    }

    /// Read one untagged startup packet. `Ok(None)` on clean EOF.
    pub async fn read_startup(&mut self) -> Result<Option<StartupPacket>> {
        loop {
            if let Some(pkt) = try_take_startup(&mut self.buf)? {
                return Ok(Some(pkt));
            }
            if self.inner.read_buf(&mut self.buf).await? == 0 {
                if self.buf.is_empty() {
                    return Ok(None);
                }
                bail!("peer closed mid-startup-packet");
            }
        }
    }
}

fn try_take_message(buf: &mut BytesMut) -> Result<Option<Message>> {
    if buf.len() < 5 {
        return Ok(None);
    }
    let len = i32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    if len < 4 {
        bail!("invalid message length {len}");
    }
    let total = 1 + len as usize;
    if buf.len() < total {
        return Ok(None);
    }
    Ok(Some(Message::from_frame(buf.split_to(total).freeze())))
}

fn try_take_startup(buf: &mut BytesMut) -> Result<Option<StartupPacket>> {
    if buf.len() < 8 {
        return Ok(None);
    }
    let len = i32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if !(8..=1_048_576).contains(&len) {
        bail!("implausible startup packet length {len}");
    }
    if buf.len() < len as usize {
        return Ok(None);
    }
    let mut frame = buf.split_to(len as usize);
    frame.advance(4);
    let code = frame.get_i32();
    Ok(Some(StartupPacket {
        code,
        body: frame.freeze(),
    }))
}

pub fn read_cstring(buf: &mut Bytes) -> Option<String> {
    let end = buf.iter().position(|b| *b == 0)?;
    let s = String::from_utf8_lossy(&buf[..end]).into_owned();
    buf.advance(end + 1);
    Some(s)
}

// --- RowDescription ---------------------------------------------------------

/// One output field's provenance, straight off the wire.
#[derive(Debug, Clone)]
pub struct FieldDescription {
    pub name: String,
    /// pg_class OID, or 0 when the field is not a plain stored-column reference.
    pub table_oid: u32,
    /// pg_attribute attnum, or 0.
    pub column_id: i16,
    pub type_oid: u32,
    pub format: i16,
}

impl FieldDescription {
    pub fn has_provenance(&self) -> bool {
        self.table_oid != 0
    }
}

pub fn parse_row_description(body: &Bytes) -> Result<Vec<FieldDescription>> {
    let mut buf = body.clone();
    if buf.remaining() < 2 {
        bail!("truncated RowDescription");
    }
    let count = buf.get_i16();
    let mut fields = Vec::with_capacity(count.max(0) as usize);
    for _ in 0..count {
        let name = read_cstring(&mut buf).ok_or_else(|| anyhow::anyhow!("bad field name"))?;
        if buf.remaining() < 18 {
            bail!("truncated RowDescription field");
        }
        let table_oid = buf.get_u32();
        let column_id = buf.get_i16();
        let type_oid = buf.get_u32();
        let _type_size = buf.get_i16();
        let _type_mod = buf.get_i32();
        let format = buf.get_i16();
        fields.push(FieldDescription {
            name,
            table_oid,
            column_id,
            type_oid,
            format,
        });
    }
    Ok(fields)
}

// --- DataRow ----------------------------------------------------------------

/// Field values of a DataRow. `None` is SQL NULL (wire length -1).
pub fn parse_data_row(body: &Bytes) -> Result<Vec<Option<Bytes>>> {
    let mut buf = body.clone();
    if buf.remaining() < 2 {
        bail!("truncated DataRow");
    }
    let count = buf.get_i16();
    let mut out = Vec::with_capacity(count.max(0) as usize);
    for _ in 0..count {
        if buf.remaining() < 4 {
            bail!("truncated DataRow field length");
        }
        let len = buf.get_i32();
        if len < 0 {
            out.push(None);
        } else {
            let len = len as usize;
            if buf.remaining() < len {
                bail!("truncated DataRow field body");
            }
            out.push(Some(buf.split_to(len)));
        }
    }
    Ok(out)
}

/// Build a `DataRow` frame directly.
///
/// Writes the tag and length prefix in place rather than building a body and
/// letting `Message::new` copy it again — this runs once per masked row, so the
/// second copy is not free.
pub fn build_data_row(values: &[Option<Bytes>]) -> Message {
    let size: usize = values
        .iter()
        .map(|v| 4 + v.as_ref().map_or(0, |b| b.len()))
        .sum();
    let mut frame = BytesMut::with_capacity(7 + size);
    frame.put_u8(B_DATA_ROW);
    frame.put_i32((6 + size) as i32);
    frame.put_i16(values.len() as i16);
    for v in values {
        match v {
            None => frame.put_i32(-1),
            Some(bytes) => {
                frame.put_i32(bytes.len() as i32);
                frame.put_slice(bytes);
            }
        }
    }
    Message::from_frame(frame.freeze())
}

// --- SASL mechanism negotiation ---------------------------------------------

/// `AuthenticationSASL` sub-code inside an `Authentication` message.
pub const AUTH_SASL: i32 = 10;

/// The SASL mechanisms a server is offering.
///
/// # Channel binding and TLS-terminating proxies
///
/// `SCRAM-SHA-256-PLUS` ties the authentication exchange to the TLS certificate
/// of the endpoint the client is talking to. pgmask terminates TLS and
/// re-originates the connection, so the client binds to *our* certificate while
/// the backend verifies against *its own*. The check fails.
///
/// That is channel binding working exactly as designed — detecting an endpoint
/// that intercepts and re-originates TLS is the entire point, and pgmask is such
/// an endpoint.
///
/// Stripping `-PLUS` from this list does not help: SCRAM carries a `gs2` flag
/// that says "I support channel binding but the server did not offer it", and a
/// server that *did* offer it treats that as the downgrade attack it is. Both
/// paths fail, by design, and neither can be fixed from inside the proxy.
///
/// The workable configuration is therefore to leave the **backend** leg
/// plaintext: Postgres only advertises `-PLUS` on a TLS connection of its own,
/// so with a plaintext backend leg it offers plain `SCRAM-SHA-256`, the client
/// authenticates normally, and the client-to-pgmask hop is still encrypted. Put
/// the proxy next to the database and secure that hop by placement.
/// Remove channel-binding mechanisms from an `AuthenticationSASL` message.
///
/// Correct **only** when the client leg is plaintext. In that case the client
/// will send the gs2 flag `n` ("I do not support channel binding"), which a
/// server accepts even though it offered `-PLUS`.
///
/// It is *wrong* when the client leg is TLS: such a client sends `y` ("I support
/// it, you did not offer it"), and a server that did offer it treats that as the
/// downgrade attack it is.
///
/// Returns `None` when nothing needed changing.
pub fn strip_channel_binding(body: &Bytes) -> Option<Bytes> {
    let mechanisms = sasl_mechanisms(body);
    if mechanisms.is_empty() || !mechanisms.iter().any(|m| m.ends_with("-PLUS")) {
        return None;
    }
    let mut out = BytesMut::new();
    out.put_i32(AUTH_SASL);
    for mechanism in mechanisms.iter().filter(|m| !m.ends_with("-PLUS")) {
        out.put_slice(mechanism.as_bytes());
        out.put_u8(0);
    }
    out.put_u8(0);
    Some(out.freeze())
}

pub fn sasl_mechanisms(body: &Bytes) -> Vec<String> {
    let mut buf = body.clone();
    if buf.len() < 4 || buf.get_i32() != AUTH_SASL {
        return Vec::new();
    }
    let mut out = Vec::new();
    while let Some(m) = read_cstring(&mut buf) {
        if m.is_empty() {
            break;
        }
        out.push(m);
    }
    out
}

// --- ErrorResponse ----------------------------------------------------------

/// Insufficient privilege. The right SQLSTATE for "policy refused this", and one
/// every driver already surfaces sensibly.
pub const SQLSTATE_INSUFFICIENT_PRIVILEGE: &str = "42501";

pub fn build_error(sqlstate: &str, message: &str, hint: Option<&str>) -> Message {
    let mut body = BytesMut::new();
    for (tag, value) in [
        (b'S', "ERROR"),
        (b'V', "ERROR"),
        (b'C', sqlstate),
        (b'M', message),
    ] {
        body.put_u8(tag);
        body.put_slice(value.as_bytes());
        body.put_u8(0);
    }
    if let Some(hint) = hint {
        body.put_u8(b'H');
        body.put_slice(hint.as_bytes());
        body.put_u8(0);
    }
    body.put_u8(0);
    Message::new(B_ERROR_RESPONSE, body.freeze())
}

/// Error/notice fields that can echo column values back to the client.
///
/// A unique-violation carries the conflicting value verbatim:
///   `DETAIL: Key (email)=(alice@example.com) already exists.`
/// That is a live exfiltration channel, so these fields are dropped whenever the
/// message mentions anything we are masking.
const LEAKY_FIELDS: &[u8] = b"DHncdtq";

/// Rebuild an Error/Notice with leaky fields removed. Returns `None` if nothing
/// needed changing, so the common path forwards the original bytes untouched.
pub fn scrub_error(body: &Bytes) -> Option<Bytes> {
    let mut buf = body.clone();
    let mut kept = BytesMut::with_capacity(body.len());
    let mut changed = false;
    loop {
        if buf.remaining() < 1 {
            break;
        }
        let field = buf.get_u8();
        if field == 0 {
            break;
        }
        let Some(value) = read_cstring(&mut buf) else {
            break;
        };
        if LEAKY_FIELDS.contains(&field) {
            changed = true;
            continue;
        }
        kept.put_u8(field);
        kept.put_slice(value.as_bytes());
        kept.put_u8(0);
    }
    if !changed {
        return None;
    }
    kept.put_u8(0);
    Some(kept.freeze())
}

// --- Frontend messages the state machine steers on --------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DescribeTarget {
    Statement(String),
    Portal(String),
}

/// `Describe` is `[kind: u8][name: cstring]`.
pub fn parse_describe(body: &Bytes) -> Option<DescribeTarget> {
    let mut buf = body.clone();
    let kind = buf.get_u8();
    let name = read_cstring(&mut buf)?;
    match kind {
        b'S' => Some(DescribeTarget::Statement(name)),
        b'P' => Some(DescribeTarget::Portal(name)),
        _ => None,
    }
}

/// `Bind` starts `[portal: cstring][statement: cstring]`; we need only those.
pub fn parse_bind(body: &Bytes) -> Option<(String, String)> {
    let mut buf = body.clone();
    let portal = read_cstring(&mut buf)?;
    let statement = read_cstring(&mut buf)?;
    Some((portal, statement))
}

/// `Execute` starts `[portal: cstring]`.
pub fn parse_execute(body: &Bytes) -> Option<String> {
    let mut buf = body.clone();
    read_cstring(&mut buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_a_tagged_message() {
        let msg = Message::new(b'Q', Bytes::from_static(b"SELECT 1\0"));
        let mut buf = BytesMut::from(&msg.encode()[..]);
        let got = try_take_message(&mut buf).unwrap().unwrap();
        assert_eq!(got.tag, b'Q');
        assert_eq!(&got.body[..], b"SELECT 1\0");
        assert!(buf.is_empty());
    }

    #[test]
    fn waits_for_a_whole_frame() {
        let msg = Message::new(b'Q', Bytes::from_static(b"SELECT 1\0"));
        let encoded = msg.encode();
        // Feed one byte at a time; nothing may be produced until the last.
        let mut buf = BytesMut::new();
        for byte in &encoded[..encoded.len() - 1] {
            buf.put_u8(*byte);
            assert!(try_take_message(&mut buf).unwrap().is_none());
        }
        buf.put_u8(encoded[encoded.len() - 1]);
        assert!(try_take_message(&mut buf).unwrap().is_some());
    }

    #[test]
    fn round_trips_a_data_row() {
        let values = vec![
            Some(Bytes::from_static(b"alice@example.com")),
            None,
            Some(Bytes::from_static(b"")),
        ];
        let msg = build_data_row(&values);
        let parsed = parse_data_row(&msg.body).unwrap();
        assert_eq!(parsed, values);
    }

    #[test]
    fn parses_row_description_provenance() {
        // One field: name="email", table_oid=16391, attnum=2, type=text, format=text.
        let mut body = BytesMut::new();
        body.put_i16(1);
        body.put_slice(b"email\0");
        body.put_u32(16391);
        body.put_i16(2);
        body.put_u32(25);
        body.put_i16(-1);
        body.put_i32(-1);
        body.put_i16(0);
        let fields = parse_row_description(&body.freeze()).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, "email");
        assert_eq!(fields[0].table_oid, 16391);
        assert_eq!(fields[0].column_id, 2);
        assert!(fields[0].has_provenance());
    }

    #[test]
    fn zero_table_oid_means_no_provenance() {
        let mut body = BytesMut::new();
        body.put_i16(1);
        body.put_slice(b"lower\0");
        body.put_u32(0);
        body.put_i16(0);
        body.put_u32(25);
        body.put_i16(-1);
        body.put_i32(-1);
        body.put_i16(0);
        let fields = parse_row_description(&body.freeze()).unwrap();
        assert!(!fields[0].has_provenance());
    }

    #[test]
    fn scrubs_detail_but_keeps_message() {
        let mut body = BytesMut::new();
        for (tag, value) in [
            (b'S', "ERROR"),
            (b'C', "23505"),
            (b'M', "duplicate key value violates unique constraint"),
            (b'D', "Key (email)=(alice@example.com) already exists."),
        ] {
            body.put_u8(tag);
            body.put_slice(value.as_bytes());
            body.put_u8(0);
        }
        body.put_u8(0);
        let scrubbed = scrub_error(&body.freeze()).expect("should have changed");
        let text = String::from_utf8_lossy(&scrubbed);
        assert!(text.contains("duplicate key"));
        assert!(!text.contains("alice@example.com"));
    }

    #[test]
    fn leaves_clean_errors_untouched() {
        let mut body = BytesMut::new();
        for (tag, value) in [(b'S', "ERROR"), (b'C', "42601"), (b'M', "syntax error")] {
            body.put_u8(tag);
            body.put_slice(value.as_bytes());
            body.put_u8(0);
        }
        body.put_u8(0);
        assert!(scrub_error(&body.freeze()).is_none());
    }

    #[test]
    fn parses_extended_protocol_steering_messages() {
        let mut bind = BytesMut::new();
        bind.put_slice(b"portal1\0stmt1\0");
        assert_eq!(
            parse_bind(&bind.freeze()),
            Some(("portal1".into(), "stmt1".into()))
        );

        let mut describe = BytesMut::new();
        describe.put_u8(b'S');
        describe.put_slice(b"stmt1\0");
        assert_eq!(
            parse_describe(&describe.freeze()),
            Some(DescribeTarget::Statement("stmt1".into()))
        );
    }
}
