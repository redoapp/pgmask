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
pub const B_PARAMETER_STATUS: u8 = b'S';
pub const B_NOTIFICATION_RESPONSE: u8 = b'A';
pub const B_READY_FOR_QUERY: u8 = b'Z';
pub const B_PARSE_COMPLETE: u8 = b'1';
pub const B_BIND_COMPLETE: u8 = b'2';
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
    b'Z', // ReadyForQuery
    b'C', // CommandComplete
    b'I', // EmptyQueryResponse
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
pub const F_PARSE: u8 = b'P';
pub const F_SYNC: u8 = b'S';
pub const F_BIND: u8 = b'B';
pub const F_CLOSE: u8 = b'C';
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
        // The length word counts itself plus the body. Every body is either a
        // slice of a frame that an i32 length already bounded, or short text
        // pgmask generated itself, so neither sum can overflow — the saturating
        // forms make that provable rather than assumed.
        let mut raw = BytesMut::with_capacity(body.len().saturating_add(5));
        raw.put_u8(tag);
        raw.put_i32(
            i32::try_from(body.len())
                .unwrap_or(i32::MAX)
                .saturating_add(4),
        );
        raw.put_slice(&body);
        let raw = raw.freeze();
        let body = raw.slice(5..);
        Self { tag, body, raw }
    }

    /// Wrap a complete frame already read off the wire.
    ///
    /// The tag is passed in rather than re-read from `raw[0]`: both callers have
    /// already established it, so there is no length assumption to restate here.
    fn from_frame(tag: u8, raw: Bytes) -> Self {
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
        // A startup body only ever comes from a packet whose length was already
        // range-checked to at most 1 MiB, so these sums cannot overflow.
        let mut out = BytesMut::with_capacity(self.body.len().saturating_add(8));
        out.put_i32(
            i32::try_from(self.body.len())
                .unwrap_or(i32::MAX)
                .saturating_add(8),
        );
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
    eof: bool,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buf: BytesMut::with_capacity(16 * 1024),
            eof: false,
        }
    }

    /// Whether the peer has closed. Lets the pump distinguish "no more messages
    /// buffered right now" from "this connection is over" with a single call
    /// site per direction.
    pub fn saw_eof(&self) -> bool {
        self.eof
    }

    /// Read one tagged message. `Ok(None)` on clean EOF.
    pub async fn read_message(&mut self) -> Result<Option<Message>> {
        loop {
            if let Some(msg) = try_take_message(&mut self.buf)? {
                return Ok(Some(msg));
            }
            if self.inner.read_buf(&mut self.buf).await? == 0 {
                self.eof = true;
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
    // Nothing can be decided until the whole `[tag][len]` header is buffered;
    // a short buffer is "not yet", not "malformed".
    let Some(&[tag, l0, l1, l2, l3]) = buf.get(..5) else {
        return Ok(None);
    };
    let len = i32::from_be_bytes([l0, l1, l2, l3]);
    if len < 4 {
        bail!("invalid message length {len}");
    }
    // `len` is attacker-controlled and counts itself but not the tag byte. A
    // total that does not fit a usize is refused rather than wrapped into a
    // small one, which would frame the next bytes as a message of our choosing.
    let Some(total) = usize::try_from(len).ok().and_then(|n| n.checked_add(1)) else {
        bail!("message length {len} does not fit this platform");
    };
    if buf.len() < total {
        return Ok(None);
    }
    Ok(Some(Message::from_frame(tag, buf.split_to(total).freeze())))
}

fn try_take_startup(buf: &mut BytesMut) -> Result<Option<StartupPacket>> {
    if buf.len() < 8 {
        return Ok(None);
    }
    // The `< 8` guard above means the four length bytes are always present.
    let Some(&[l0, l1, l2, l3]) = buf.get(..4) else {
        return Ok(None);
    };
    let len = i32::from_be_bytes([l0, l1, l2, l3]);
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

/// Length-checked, so a truncated or hostile frame returns `None` rather than
/// panicking on a slice out of range.
fn read_i16(buf: &mut Bytes) -> Option<i16> {
    if buf.len() < 2 {
        return None;
    }
    Some(buf.get_i16())
}

fn read_i32(buf: &mut Bytes) -> Option<i32> {
    if buf.len() < 4 {
        return None;
    }
    Some(buf.get_i32())
}

pub fn read_cstring(buf: &mut Bytes) -> Option<String> {
    Some(String::from_utf8_lossy(&read_cstring_bytes(buf)?).into_owned())
}

/// Read a protocol cstring without interpreting its bytes.
///
/// Prepared-statement and portal names are protocol identities, not text for
/// pgmask to normalize. Lossy UTF-8 decoding collapses distinct byte strings
/// onto the same replacement character and therefore cannot be used as a map
/// key.
fn read_cstring_bytes(buf: &mut Bytes) -> Option<Bytes> {
    let end = buf.iter().position(|b| *b == 0)?;
    // `position` found the NUL inside the buffer, so `end` is a valid split
    // point and one byte remains for the terminator.
    let value = buf.split_to(end);
    buf.advance(1);
    Some(value)
}

/// SQL is analyzed as UTF-8. Unsupported client encodings stay unknown so the
/// release decision fails closed instead of analyzing replacement characters.
fn read_utf8_cstring(buf: &mut Bytes) -> Option<String> {
    String::from_utf8(read_cstring_bytes(buf)?.to_vec()).ok()
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
    if count < 0 {
        bail!("negative RowDescription field count");
    }
    let mut fields = Vec::with_capacity(count as usize);
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
    if !buf.is_empty() {
        bail!("trailing bytes in RowDescription");
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
    if count < 0 {
        bail!("negative DataRow field count");
    }
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        if buf.remaining() < 4 {
            bail!("truncated DataRow field length");
        }
        let len = buf.get_i32();
        if len == -1 {
            out.push(None);
        } else if len < -1 {
            bail!("invalid negative DataRow field length");
        } else {
            let len = len as usize;
            if buf.remaining() < len {
                bail!("truncated DataRow field body");
            }
            out.push(Some(buf.split_to(len)));
        }
    }
    if !buf.is_empty() {
        bail!("trailing bytes in DataRow");
    }
    Ok(out)
}

/// Build a `DataRow` frame directly.
///
/// Writes the tag and length prefix in place rather than building a body and
/// letting `Message::new` copy it again — this runs once per masked row, so the
/// second copy is not free.
pub fn build_data_row(values: &[Option<Bytes>]) -> Message {
    // Each field costs a 4-byte length plus its bytes. The values came out of a
    // frame that an i32 length already bounded and masks do not grow a row by
    // orders of magnitude, so these sums cannot approach `usize::MAX`;
    // saturating keeps the arithmetic total on a path that has no caller-visible
    // failure mode.
    let size = values.iter().fold(0usize, |acc, v| {
        acc.saturating_add(4)
            .saturating_add(v.as_ref().map_or(0, |b| b.len()))
    });
    let mut frame = BytesMut::with_capacity(size.saturating_add(7));
    frame.put_u8(B_DATA_ROW);
    frame.put_i32(i32::try_from(size).unwrap_or(i32::MAX).saturating_add(6));
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
    Message::from_frame(B_DATA_ROW, frame.freeze())
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
/// That is a live exfiltration channel, so these fields are dropped from every
/// error and notice, unconditionally.
///
/// Not "when the message mentions a masked column", which is what this said and
/// what a reader would reasonably implement from it. Deciding per message means
/// parsing prose written by the server in an unknown locale to work out which
/// column it is about — and being wrong once, in the direction of keeping the
/// field, is the disclosure. Dropping always costs error detail on unmasked
/// columns, which is a diagnosability cost the operator can see and complain
/// about; the other failure is silent.
///
/// `W` — the `CONTEXT` traceback — was added after it was found carrying a
/// value. It reproduces the text of a statement PL/pgSQL executed, so
///
/// ```sql
/// DO $$ DECLARE v text; BEGIN
///   SELECT email INTO v FROM canary.subjects LIMIT 1;
///   EXECUTE 'SELECT 1/0 -- ' || v;
/// END $$;
/// ```
///
/// returned `CONTEXT: SQL statement "SELECT 1/0 -- alice@example.com"` through
/// the proxy. Same shape as `q`, which was already here.
const LEAKY_FIELDS: &[u8] = b"DHncdtqW";

/// A `NoticeResponse`'s primary message is written by SQL, so it is dropped too.
///
/// `LEAKY_FIELDS` covers the fields Postgres fills from row data. The *primary*
/// message of a notice is different: the client chooses it outright.
///
/// ```sql
/// DO $$ BEGIN RAISE NOTICE '%', (SELECT email FROM demo.customers LIMIT 1); END $$;
/// ```
///
/// returned `NOTICE:  user1@example.com` through the proxy while the same
/// column read as a pseudonym — a complete bypass of the control, confirmed
/// against a live server.
const NOTICE_WITHHELD: &str = "pgmask: notice text withheld (it is written by SQL)";

/// An error's primary message is chosen by SQL just as often, and this was
/// missed for four releases.
///
/// The reasoning that kept it said Postgres "composes error messages from its
/// own text rather than from a row", and that `relation does not exist` is the
/// difference between a usable proxy and an opaque one. The first half is
/// false:
///
/// ```sql
/// DO $$ BEGIN RAISE EXCEPTION '%', (SELECT email FROM canary.subjects LIMIT 1); END $$;
/// ```
///
/// returns the address verbatim — the identical channel to the notice above,
/// through the other message type, and `examples/demo/verify.sh` checked the
/// notice in both directions while checking only that an ordinary backend error
/// survived. `RAISE` accepts an expression for the message; there is no locale-
/// independent way to tell a message Postgres wrote from one a client did.
///
/// The `SQLSTATE` is kept, so a client still gets `42P01` for a missing
/// relation. That is the machine-readable half of what it lost, and every
/// driver surfaces it.
/// Deliberately not prefixed `pgmask:`.
///
/// That prefix means **the proxy refused this statement** — five harnesses key
/// off `message().starts_with("pgmask:")` and so, presumably, do operators.
/// Using it here made every backend error read as a refusal: the generated
/// campaign's counts diverged from the proxy's own metrics by 20,034
/// statements, all of them ordinary SQL errors reclassified.
///
/// The distinction is real and worth keeping in the wording. "The proxy would
/// not run this" and "your statement failed and the reason is withheld" are
/// different things to be told at three in the morning.
const ERROR_WITHHELD: &str = "error text withheld by pgmask (SQL can choose it); see the SQLSTATE";

/// When the `SQLSTATE` is client-chosen too, it is five characters of anything.
///
/// `RAISE ... USING ERRCODE` takes an expression, and a SQLSTATE is five
/// characters of `[0-9A-Z]`, so
///
/// ```sql
/// DO $$ BEGIN RAISE EXCEPTION 'x'
///   USING ERRCODE = upper(substr((SELECT email FROM canary.subjects LIMIT 1), 1, 5));
/// END $$;
/// ```
///
/// returns five characters of the value per query. Measured, not theorised:
/// `CANAR` came back through the proxy after the message and `CONTEXT` were
/// closed. That is roughly five queries for an address, against the 313 the
/// documented `count(*)` predicate oracle needs — a faster channel than the
/// inference routes the design puts out of scope.
///
/// HOW THIS TELLS THE TWO APART
///
/// A client-chosen code always arrives with a `CONTEXT` field, because `RAISE`
/// only exists inside PL/pgSQL and a function frame always produces one.
/// Ordinary backend errors have none — measured on Postgres 17:
///
/// ```text
///   SELECT * FROM nope      ERROR: 42P01 ...          (no CONTEXT)
///   SELECT 1/0              ERROR: 22012 ...          (no CONTEXT)
///   SELECT 'x'::int         ERROR: 22P02 ...          (no CONTEXT)
///   DO $$ RAISE ... $$      ERROR: P0001 ...  CONTEXT: PL/pgSQL function ...
/// ```
///
/// So the code is kept when there is no `CONTEXT` and replaced when there is.
/// The cost is that a genuine error raised inside a function loses its
/// `SQLSTATE` as well — over-withholding, in the direction that does not
/// disclose. An application whose PL/pgSQL raises custom SQLSTATEs for business
/// logic will notice; that is the same trade as the message, and it is visible.
const WITHHELD_SQLSTATE: &str = "XX000";
const ERROR_WITHHELD_WITH_CODE: &str =
    "error text and SQLSTATE withheld by pgmask (SQL can choose both)";

/// Rebuild an Error/Notice with leaky fields removed. Returns `None` if nothing
/// needed changing, so the common path forwards the original bytes untouched.
///
/// The primary message is replaced for both kinds — `RAISE NOTICE` and
/// `RAISE EXCEPTION` are the same channel — with different fixed text, because
/// an error keeps its `SQLSTATE` and a notice has nothing to point the reader
/// at.
pub fn scrub_error(body: &Bytes) -> Option<Bytes> {
    scrub_diagnostic(body, false)
}

/// As [`scrub_error`], for a `NoticeResponse`.
pub fn scrub_notice(body: &Bytes) -> Option<Bytes> {
    scrub_diagnostic(body, true)
}

/// Is this field present at all? Used to read `W` before the rebuild drops it.
fn has_field(body: &Bytes, wanted: u8) -> bool {
    let mut buf = body.clone();
    loop {
        if buf.remaining() < 1 {
            return false;
        }
        let field = buf.get_u8();
        if field == 0 {
            return false;
        }
        if read_cstring(&mut buf).is_none() {
            return false;
        }
        if field == wanted {
            return true;
        }
    }
}

fn scrub_diagnostic(body: &Bytes, notice: bool) -> Option<Bytes> {
    // Whether the SQLSTATE was the client's to choose. Read first because `W` is
    // dropped in the rebuild and would be gone by then.
    //
    // Always true for a notice. `RAISE NOTICE 'x' USING ERRCODE = …` takes an
    // expression exactly as `RAISE EXCEPTION` does, and the first version of
    // this fix wrote `!notice && …`, which left it open — measured, five
    // characters of the canary came back. A notice is the *worse* of the two
    // channels: it does not abort the transaction, so
    //
    // ```sql
    // DO $$ BEGIN FOR i IN 1..10 LOOP
    //   RAISE NOTICE 'x' USING ERRCODE = <five characters of the value>;
    // END LOOP; END $$;
    // ```
    //
    // carries the whole value in one statement. Nothing is lost by withholding
    // it: a notice's text is already replaced unconditionally, so its SQLSTATE
    // has nothing left to qualify.
    let from_user_sql = notice || has_field(body, b'W');
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
        if field == b'M' {
            changed = true;
            kept.put_u8(b'M');
            kept.put_slice(
                match (notice, from_user_sql) {
                    (true, _) => NOTICE_WITHHELD,
                    (false, false) => ERROR_WITHHELD,
                    (false, true) => ERROR_WITHHELD_WITH_CODE,
                }
                .as_bytes(),
            );
            kept.put_u8(0);
            continue;
        }
        // The protocol requires a code, so it is replaced rather than dropped.
        if from_user_sql && field == b'C' {
            changed = true;
            kept.put_u8(b'C');
            kept.put_slice(WITHHELD_SQLSTATE.as_bytes());
            kept.put_u8(0);
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

/// GUCs Postgres reports on change, none of which a client can fill with row
/// data.
///
/// `application_name` is deliberately absent. It is the one reportable GUC
/// whose value is free text, and
///
/// ```sql
/// DO $$ BEGIN PERFORM set_config('application_name',
///          (SELECT email FROM demo.customers LIMIT 1), false); END $$;
/// ```
///
/// puts a masked value in a `ParameterStatus` that no `RowDescription` governs.
/// Withholding the echo costs a client the confirmation of a name it chose
/// itself; forwarding it costs the whole control.
///
/// An allowlist rather than a denylist because an extension can mark its own
/// GUC as `GUC_REPORT` with arbitrary text, and a denylist cannot know its name.
const REPORTABLE_GUCS: &[&str] = &[
    "client_encoding",
    "DateStyle",
    "default_transaction_read_only",
    "in_hot_standby",
    "integer_datetimes",
    "IntervalStyle",
    "is_superuser",
    // `scram_iterations` was here and is a disclosure. It is the one reportable
    // GUC that takes an arbitrary integer over a huge range, so unlike every
    // other entry it carries a *value* rather than a choice from a vocabulary:
    //
    // ```sql
    // DO $$ BEGIN PERFORM set_config('scram_iterations',
    //          (SELECT annual_salary FROM demo.employees LIMIT 1)::text, false); END $$;
    // ```
    //
    // came back as a `ParameterStatus` carrying the number. Measured: `987001`,
    // derived from a masked column, arrived through the proxy while a control
    // setting `TimeZone` to a constant proved the channel was live.
    //
    // What withholding it costs: libpq reads it to hash a new password client
    // side and falls back to 4096 without it. Setting a password through a
    // masking proxy is not the workload this is for.
    //
    // THE LENS THIS NEEDED
    //
    // The allowlist was reviewed for *which GUCs* a client can set, and every
    // other entry is a boolean, a fixed vocabulary, an existing role name, or
    // server-fixed — a few bits each, the covert-channel category. It was not
    // reviewed for *what shape of value* each accepts, and that is the question
    // that matters: a GUC taking a 31-bit integer is a column read.
    "server_encoding",
    "server_version",
    "session_authorization",
    "standard_conforming_strings",
    "TimeZone",
];

/// Whether this `ParameterStatus` may be forwarded.
pub fn parameter_status_is_safe(body: &Bytes) -> bool {
    let mut buf = body.clone();
    read_cstring(&mut buf).is_some_and(|key| REPORTABLE_GUCS.iter().any(|safe| *safe == key))
}

// --- Frontend messages the state machine steers on --------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DescribeTarget {
    Statement(Bytes),
    Portal(Bytes),
}

/// `Describe` is `[kind: u8][name: cstring]`.
pub fn parse_describe(body: &Bytes) -> Option<DescribeTarget> {
    let mut buf = body.clone();
    // `get_u8` panics on an empty body, and a zero-length Describe is one frame
    // a hostile client can send. Treat it like any other unparseable Describe:
    // no target, so no slot is queued and the coming RowDescription is planned
    // from scratch instead of inheriting one.
    if buf.is_empty() {
        return None;
    }
    let kind = buf.get_u8();
    let name = read_cstring_bytes(&mut buf)?;
    match kind {
        b'S' => Some(DescribeTarget::Statement(name)),
        b'P' => Some(DescribeTarget::Portal(name)),
        _ => None,
    }
}

/// `Close` has the same `[kind: u8][name: cstring]` target layout as
/// `Describe`, so share the strict parser rather than maintaining two copies.
pub fn parse_close(body: &Bytes) -> Option<DescribeTarget> {
    parse_describe(body)
}

/// `Bind` starts `[portal: cstring][statement: cstring]`; we need only those.
pub fn parse_bind(body: &Bytes) -> Option<(Bytes, Bytes)> {
    let mut buf = body.clone();
    let portal = read_cstring_bytes(&mut buf)?;
    let statement = read_cstring_bytes(&mut buf)?;
    Some((portal, statement))
}

/// Result format codes from a `Bind`.
///
/// **These, not the `RowDescription`, decide how row values are encoded.**
/// `Describe(Statement)` reports every field as format 0, because the client
/// has not chosen yet — the choice is made at `Bind`. A plan that took the
/// format from the description therefore believed "text" while a driver
/// requesting binary sent four-byte dates, and masking failed on every one.
///
/// Layout after the two cstrings:
/// `[i16 n_param_formats][i16 * n][i16 n_params][(i32 len + bytes) * n]
///  [i16 n_result_formats][i16 * n]`
///
/// Per the protocol, `n_result_formats` of 0 means "all text" and 1 means "this
/// one code applies to every column".
pub fn parse_bind_result_formats(body: &Bytes) -> Option<Vec<i16>> {
    let mut buf = body.clone();
    let _portal = read_cstring_bytes(&mut buf)?;
    let _statement = read_cstring_bytes(&mut buf)?;

    let n_param_formats = read_i16(&mut buf)?;
    for _ in 0..n_param_formats.max(0) {
        read_i16(&mut buf)?;
    }
    let n_params = read_i16(&mut buf)?;
    for _ in 0..n_params.max(0) {
        let len = read_i32(&mut buf)?;
        if len > 0 {
            let len = usize::try_from(len).ok()?;
            if buf.len() < len {
                return None;
            }
            let _ = buf.split_to(len);
        }
    }
    let n_result_formats = read_i16(&mut buf)?;
    let mut formats = Vec::new();
    for _ in 0..n_result_formats.max(0) {
        formats.push(read_i16(&mut buf)?);
    }
    Some(formats)
}

/// The format for output field `index`, given a `Bind`'s result format codes.
pub fn format_for(formats: &[i16], index: usize) -> i16 {
    match formats {
        [] => 0,
        // One code applies to every column, per the Bind message spec.
        [only] => *only,
        _ => formats.get(index).copied().unwrap_or(0),
    }
}

/// A simple `Query` is a single cstring.
pub fn parse_simple_query(body: &Bytes) -> Option<String> {
    let mut buf = body.clone();
    read_utf8_cstring(&mut buf)
}

/// `Parse` is `[statement: cstring][query: cstring][...]`.
pub fn parse_parse(body: &Bytes) -> Option<(Bytes, String)> {
    let mut buf = body.clone();
    let name = read_cstring_bytes(&mut buf)?;
    let sql = read_utf8_cstring(&mut buf)?;
    Some((name, sql))
}

/// `Execute` starts `[portal: cstring]`.
pub fn parse_execute(body: &Bytes) -> Option<Bytes> {
    let mut buf = body.clone();
    read_cstring_bytes(&mut buf)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;

    #[test]
    fn row_parsers_reject_unaccounted_bytes_and_negative_counts() {
        let mut trailing = BytesMut::new();
        trailing.put_i16(0);
        trailing.put_slice(b"unvetted suffix");
        assert!(parse_data_row(&trailing.clone().freeze()).is_err());
        assert!(parse_row_description(&trailing.freeze()).is_err());

        let mut negative = BytesMut::new();
        negative.put_i16(-1);
        assert!(parse_data_row(&negative.clone().freeze()).is_err());
        assert!(parse_row_description(&negative.freeze()).is_err());

        let mut bad_length = BytesMut::new();
        bad_length.put_i16(1);
        bad_length.put_i32(-2);
        assert!(parse_data_row(&bad_length.freeze()).is_err());
    }

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

    /// The two functions that decide whether authentication downgrades.
    ///
    /// Neither had a test anywhere in the repository — not a unit test, not a
    /// suite, not the demo. The mutation campaign flagged both guards in
    /// `session.rs` that call them, which is what a function with no coverage
    /// looks like from the outside.
    ///
    /// They matter because the proxy terminates TLS: Postgres advertises
    /// `-PLUS` on its own TLS leg, the client cannot satisfy channel binding
    /// against a certificate the proxy holds, and stripping is the only way a
    /// plaintext client connects at all. Getting it wrong in one direction
    /// breaks every login; in the other it strips for a TLS client, which the
    /// server correctly reads as a downgrade attack.
    fn sasl_body(mechanisms: &[&str]) -> Bytes {
        let mut b = BytesMut::new();
        b.put_i32(AUTH_SASL);
        for m in mechanisms {
            b.put_slice(m.as_bytes());
            b.put_u8(0);
        }
        b.put_u8(0);
        b.freeze()
    }

    /// A `Bind` carrying parameters, so the skip logic is exercised rather than
    /// stepped over.
    fn bind_body(params: &[&[u8]], result_formats: &[i16]) -> Bytes {
        let mut b = BytesMut::new();
        b.put_slice(b"portal\0");
        b.put_slice(b"stmt\0");
        b.put_i16(0); // no parameter format codes
        b.put_i16(i16::try_from(params.len()).unwrap());
        for p in params {
            b.put_i32(i32::try_from(p.len()).unwrap());
            b.put_slice(p);
        }
        b.put_i16(i16::try_from(result_formats.len()).unwrap());
        for f in result_formats {
            b.put_i16(*f);
        }
        b.freeze()
    }

    /// The result-format codes, which decide how every masked value is decoded.
    ///
    /// Both this and `format_for` were reached only by the never-panics
    /// properties — `let _ = parse_bind_result_formats(&body)` — which assert
    /// nothing about the answer, so every value-replacing mutant survived:
    /// `Some(vec![])`, `Some(vec![0])`, `Some(vec![1])`, `None`.
    ///
    /// Nothing else would have caught it either. The canary fixture is entirely
    /// text columns, and for text-family types the text and binary encodings
    /// are the same bytes, so a wrong format changes nothing there. It changes
    /// everything for a date, a numeric or a uuid.
    #[test]
    fn bind_result_formats_are_read_including_past_the_parameters() {
        assert_eq!(
            parse_bind_result_formats(&bind_body(&[], &[])),
            Some(vec![])
        );
        assert_eq!(
            parse_bind_result_formats(&bind_body(&[], &[1])),
            Some(vec![1])
        );
        assert_eq!(
            parse_bind_result_formats(&bind_body(&[], &[0, 1, 0])),
            Some(vec![0, 1, 0])
        );
        // Parameters have to be stepped over by length, or the codes are read
        // out of the middle of a parameter value.
        assert_eq!(
            parse_bind_result_formats(&bind_body(&[b"alice", b"", b"\x00\x01\x02"], &[1, 0])),
            Some(vec![1, 0])
        );
        // Truncated after the count is not "no formats"; it is unreadable.
        let mut short = BytesMut::new();
        short.put_slice(b"p\0s\0");
        short.put_i16(0);
        short.put_i16(0);
        short.put_i16(3); // claims three codes and supplies none
        assert_eq!(parse_bind_result_formats(&short.freeze()), None);
        assert_eq!(parse_bind_result_formats(&Bytes::new()), None);
    }

    /// One code applies to *every* column — the protocol rule that is easy to
    /// read past, and the one a mutant returning a constant hides.
    #[test]
    fn a_single_result_format_code_governs_every_column() {
        assert_eq!(format_for(&[], 0), 0, "no codes means all text");
        assert_eq!(format_for(&[], 7), 0);

        assert_eq!(format_for(&[1], 0), 1);
        assert_eq!(format_for(&[1], 3), 1, "one code is not just for column 0");
        assert_eq!(format_for(&[0], 3), 0);

        assert_eq!(format_for(&[0, 1, 0], 0), 0);
        assert_eq!(format_for(&[0, 1, 0], 1), 1);
        assert_eq!(format_for(&[0, 1, 0], 2), 0);
        // More columns than codes: text, rather than reusing the last code.
        assert_eq!(format_for(&[0, 1, 0], 9), 0);
    }

    #[test]
    fn sasl_mechanisms_reads_what_the_server_offered() {
        assert_eq!(
            sasl_mechanisms(&sasl_body(&["SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"])),
            vec!["SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"]
        );
        assert_eq!(
            sasl_mechanisms(&sasl_body(&["SCRAM-SHA-256"])),
            vec!["SCRAM-SHA-256"]
        );
        assert!(sasl_mechanisms(&sasl_body(&[])).is_empty());

        // Not a SASL message: a different authentication sub-code must not be
        // read as an empty mechanism list, because "empty" is the condition the
        // caller treats as "the server offers only channel binding".
        let mut ok = BytesMut::new();
        ok.put_i32(0); // AuthenticationOk
        assert!(sasl_mechanisms(&ok.freeze()).is_empty());

        // The case that makes the sub-code check load-bearing, and the reason
        // an `AuthenticationOk` fixture is not enough: a non-SASL auth message
        // *with a payload*. `AuthenticationMD5Password` carries a 4-byte salt,
        // and a salt containing a NUL reads as a perfectly good mechanism name
        // if nothing checks that the sub-code is 10.
        let mut md5 = BytesMut::new();
        md5.put_i32(5);
        md5.put_slice(b"AB\0C");
        assert!(
            sasl_mechanisms(&md5.freeze()).is_empty(),
            "an MD5 salt is not a mechanism list"
        );
        assert!(
            sasl_mechanisms(&Bytes::from_static(b"\x00\x00")).is_empty(),
            "truncated"
        );
        assert!(sasl_mechanisms(&Bytes::new()).is_empty(), "empty");
    }

    #[test]
    fn channel_binding_is_stripped_only_when_there_is_something_to_strip() {
        // The ordinary case: both offered, the -PLUS one goes.
        let stripped = strip_channel_binding(&sasl_body(&["SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"]))
            .expect("something to strip");
        assert_eq!(sasl_mechanisms(&stripped), vec!["SCRAM-SHA-256"]);

        // `None` means "forward the original untouched", so returning `Some` of
        // an identical body here would be a needless rewrite of an auth message.
        assert!(
            strip_channel_binding(&sasl_body(&["SCRAM-SHA-256"])).is_none(),
            "nothing to strip"
        );
        assert!(
            strip_channel_binding(&sasl_body(&[])).is_none(),
            "no mechanisms"
        );
        assert!(
            strip_channel_binding(&Bytes::new()).is_none(),
            "not a SASL message"
        );

        // Only channel binding on offer. Stripping leaves an empty list, and
        // the caller turns that into a refusal rather than a login that cannot
        // succeed — so the empty list has to actually come back.
        let only_plus = strip_channel_binding(&sasl_body(&["SCRAM-SHA-256-PLUS"]))
            .expect("a -PLUS mechanism is something to strip");
        assert!(
            sasl_mechanisms(&only_plus).is_empty(),
            "the caller keys its refusal off this being empty"
        );
    }

    #[test]
    fn scrubs_detail_and_message_but_keeps_a_backend_sqlstate() {
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
        assert!(!text.contains("alice@example.com"), "the DETAIL value");
        // The message used to be asserted present here. `RAISE EXCEPTION` lets
        // SQL write one, so it goes; the SQLSTATE is what has to survive, and
        // this error has no CONTEXT so the code is Postgres' own.
        assert!(
            !text.contains("duplicate key"),
            "the message is SQL-choosable"
        );
        assert!(text.contains("23505"), "but the SQLSTATE stays");
        assert!(text.contains(ERROR_WITHHELD));
    }

    /// Every error is rebuilt now, so the untouched fast path is unreachable
    /// for one.
    ///
    /// This asserted `scrub_error(...).is_none()` for an error with no leaky
    /// field. The primary message is always replaced and the protocol requires
    /// one, so `changed` is always set. The `Option` is kept because the call
    /// sites read better for it and a malformed frame with no fields at all
    /// still returns `None`, but nothing real takes that path.
    #[test]
    fn every_error_is_rebuilt_because_its_message_is_always_replaced() {
        let mut body = BytesMut::new();
        for (tag, value) in [(b'S', "ERROR"), (b'C', "42601"), (b'M', "syntax error")] {
            body.put_u8(tag);
            body.put_slice(value.as_bytes());
            body.put_u8(0);
        }
        body.put_u8(0);
        let scrubbed = scrub_error(&body.freeze()).expect("no fast path for an error");
        let text = String::from_utf8_lossy(&scrubbed);
        assert!(!text.contains("syntax error"));
        assert!(text.contains("42601"), "a backend SQLSTATE is forwarded");

        // A frame with no fields has nothing to change.
        assert!(scrub_error(&Bytes::from_static(b"\0")).is_none());
    }

    /// A CONTEXT means the error came through user SQL, so the code goes too.
    #[test]
    fn a_sqlstate_is_replaced_when_a_context_shows_sql_chose_it() {
        let mut body = BytesMut::new();
        for (tag, value) in [
            (b'S', "ERROR"),
            (b'C', "CANAR"),
            (b'M', "x"),
            (b'W', "PL/pgSQL function inline_code_block line 1 at RAISE"),
        ] {
            body.put_u8(tag);
            body.put_slice(value.as_bytes());
            body.put_u8(0);
        }
        body.put_u8(0);
        let scrubbed = scrub_error(&body.freeze()).expect("should have changed");
        let text = String::from_utf8_lossy(&scrubbed);
        assert!(
            !text.contains("CANAR"),
            "five characters of a value is a value"
        );
        assert!(text.contains(WITHHELD_SQLSTATE));
        assert!(
            !text.contains("PL/pgSQL"),
            "the CONTEXT itself goes as well"
        );
        assert!(text.contains(ERROR_WITHHELD_WITH_CODE));
    }

    #[test]
    fn parses_extended_protocol_steering_messages() {
        let mut bind = BytesMut::new();
        bind.put_slice(b"portal1\0stmt1\0");
        assert_eq!(
            parse_bind(&bind.freeze()),
            Some((Bytes::from_static(b"portal1"), Bytes::from_static(b"stmt1")))
        );

        let mut describe = BytesMut::new();
        describe.put_u8(b'S');
        describe.put_slice(b"stmt1\0");
        assert_eq!(
            parse_describe(&describe.freeze()),
            Some(DescribeTarget::Statement(Bytes::from_static(b"stmt1")))
        );

        let mut close = BytesMut::new();
        close.put_u8(b'P');
        close.put_slice(b"portal1\0");
        assert_eq!(
            parse_close(&close.freeze()),
            Some(DescribeTarget::Portal(Bytes::from_static(b"portal1")))
        );

        let mut distinct = Bytes::from_static(b"\x80\0\x81\0");
        let first = read_cstring_bytes(&mut distinct).expect("first name");
        let second = read_cstring_bytes(&mut distinct).expect("second name");
        assert_ne!(first, second, "protocol identities must remain byte-exact");
    }
}
