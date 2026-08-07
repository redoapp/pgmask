//! The per-connection state machine.
//!
//! One client connection, one backend connection, no multiplexing. Both
//! directions are driven from a single `select!` loop so all state lives in one
//! place with no locking — for a security boundary, "where is the plan right
//! now" should have exactly one answer.
//!
//! # The governing rule
//!
//! **The masking plan is bound to the `RowDescription`, never to the statement.**
//!
//! Every row-producing path in the protocol emits a `RowDescription` first —
//! cursors, `FETCH`, multi-statement simple queries, resumed portals, functions.
//! So they are all covered without special handling, and the only two paths that
//! emit rows *without* one, `COPY ... TO STDOUT` and the legacy `FunctionCall`,
//! are refused outright.
//!
//! Corollary, enforced below: a `DataRow` with no active plan is a bug or an
//! attack. It is never forwarded.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::catalog::{Catalog, Config, Opaque, Unclassified};
use crate::mask::{Mask, Masker};
use crate::protocol::{self, DescribeTarget, FrameReader, Message};

/// What to do with one output field.
#[derive(Debug, Clone, Copy)]
struct FieldPlan {
    mask: Mask,
    type_oid: u32,
}

type Plan = Arc<Vec<FieldPlan>>;

/// Why a result set was refused, in the words the client will see.
struct Rejection {
    message: String,
    hint: Option<String>,
}

pub struct Policy {
    pub catalog: Arc<Catalog>,
    pub masker: Arc<Masker>,
    pub unclassified: Unclassified,
    pub unclassified_mask: Mask,
    pub opaque: Opaque,
}

impl Policy {
    pub fn from_config(config: &Config, catalog: Arc<Catalog>) -> Self {
        Self {
            catalog,
            masker: Arc::new(Masker::new(config.pseudonym_key.clone().into_bytes())),
            unclassified: config.unclassified,
            unclassified_mask: config.unclassified_mask,
            opaque: config.opaque,
        }
    }

    /// Decide the plan for a described result set, or refuse it.
    fn plan_for(&self, fields: &[protocol::FieldDescription]) -> Result<Plan, Rejection> {
        let mut plan = Vec::with_capacity(fields.len());
        for field in fields {
            let mask = if !field.has_provenance() {
                match self.opaque {
                    Opaque::Reject => {
                        return Err(Rejection {
                            message: format!(
                                "pgmask: output column \"{}\" has no column provenance, so it \
                                 cannot be classified",
                                field.name
                            ),
                            hint: Some(
                                "Select the underlying column directly. Expressions, set \
                                 operations (UNION/INTERSECT/EXCEPT), recursive CTEs and \
                                 SETOF-returning functions all erase provenance."
                                    .into(),
                            ),
                        })
                    }
                    Opaque::Mask => Mask::Null,
                }
            } else {
                match self.catalog.lookup(field.table_oid, field.column_id) {
                    Some(mask) => mask,
                    None => match self.unclassified {
                        Unclassified::Mask => self.unclassified_mask,
                        Unclassified::Allow => Mask::None,
                    },
                }
            };

            // Catch type/mask mismatches once here rather than per row.
            if mask.needs_text_family() && !protocol::is_text_family(field.type_oid) {
                let name = self
                    .catalog
                    .name_of(field.table_oid, field.column_id)
                    .unwrap_or(&field.name)
                    .to_string();
                return Err(Rejection {
                    message: format!(
                        "pgmask: mask {mask:?} on {name} rewrites values as text, but its type \
                         (OID {}, wire format {}) is not a text type",
                        field.type_oid,
                        if field.format == 1 { "binary" } else { "text" },
                    ),
                    hint: Some("Use mask = \"null\" for this column.".into()),
                });
            }

            plan.push(FieldPlan {
                mask,
                type_oid: field.type_oid,
            });
        }
        Ok(Arc::new(plan))
    }
}

/// Outbound bytes accumulated across a whole read batch.
///
/// Contiguous buffers, not `Vec<Bytes>`: a vector of frames still costs one
/// `write` syscall per frame, which on a bulk result set is a syscall per row.
/// Copying each frame into one buffer and issuing a single write is far cheaper
/// than the syscalls it replaces — that change alone took per-row overhead from
/// ~2.1us to well under a microsecond.
#[derive(Default)]
struct Batch {
    to_client: BytesMut,
    to_backend: BytesMut,
    close: bool,
}

impl Batch {
    fn client(&mut self, bytes: Bytes) {
        self.to_client.put_slice(&bytes);
    }
    fn backend(&mut self, bytes: Bytes) {
        self.to_backend.put_slice(&bytes);
    }
    fn is_empty(&self) -> bool {
        self.to_client.is_empty() && self.to_backend.is_empty()
    }
}

pub struct Session {
    policy: Arc<Policy>,
    /// Plans keyed by prepared-statement name, populated by `Describe('S')`.
    statement_plans: HashMap<String, Plan>,
    /// Plans keyed by portal name, copied from the statement at `Bind`.
    portal_plans: HashMap<String, Plan>,
    /// The plan the next `DataRow` will be masked with.
    active_plan: Option<Plan>,
    /// `Describe` targets awaiting a `RowDescription`/`NoData`, in order.
    pending_describes: VecDeque<DescribeTarget>,
    /// Discarding backend traffic after a refusal, until `ReadyForQuery`.
    suppressing: bool,
    pub masked_fields: u64,
    pub rejected_result_sets: u64,
}

impl Session {
    pub fn new(policy: Arc<Policy>) -> Self {
        Self {
            policy,
            statement_plans: HashMap::new(),
            portal_plans: HashMap::new(),
            active_plan: None,
            pending_describes: VecDeque::new(),
            suppressing: false,
            masked_fields: 0,
            rejected_result_sets: 0,
        }
    }

    /// Refuse the in-flight result set: tell the client, swallow the backend's
    /// rows, and let the real `ReadyForQuery` through so transaction state stays
    /// consistent.
    fn reject(&mut self, rejection: Rejection, out: &mut Batch) {
        self.suppressing = true;
        self.active_plan = None;
        self.rejected_result_sets += 1;
        let err = protocol::build_error(
            protocol::SQLSTATE_INSUFFICIENT_PRIVILEGE,
            &rejection.message,
            rejection.hint.as_deref(),
        );
        out.client(err.encode());
    }

    fn handle_frontend(&mut self, msg: Message, out: &mut Batch) {
        match msg.tag {
            // Emits rows with no RowDescription. One of exactly two such paths.
            protocol::F_FUNCTION_CALL => {
                let err = protocol::build_error(
                    protocol::SQLSTATE_INSUFFICIENT_PRIVILEGE,
                    "pgmask: the legacy FunctionCall protocol message is not permitted",
                    Some("It returns data without a RowDescription, so it cannot be masked."),
                );
                {
                    out.client(err.encode());
                    out.close = true;
                }
            }

            // A new simple query invalidates everything: if the backend does not
            // describe the next result set, we must not mask it with a stale plan.
            protocol::F_QUERY => {
                self.active_plan = None;
                self.pending_describes.clear();
                out.backend(msg.encode())
            }

            protocol::F_BIND => {
                if let Some((portal, statement)) = protocol::parse_bind(&msg.body) {
                    match self.statement_plans.get(&statement) {
                        Some(plan) => {
                            self.portal_plans.insert(portal, plan.clone());
                        }
                        None => {
                            self.portal_plans.remove(&portal);
                        }
                    }
                }
                out.backend(msg.encode())
            }

            protocol::F_DESCRIBE => {
                if let Some(target) = protocol::parse_describe(&msg.body) {
                    self.pending_describes.push_back(target);
                }
                out.backend(msg.encode())
            }

            protocol::F_EXECUTE => {
                if let Some(portal) = protocol::parse_execute(&msg.body) {
                    self.active_plan = self.portal_plans.get(&portal).cloned();
                }
                out.backend(msg.encode())
            }

            protocol::F_TERMINATE => {
                out.backend(msg.encode());
                out.close = true;
            }

            _ => out.backend(msg.encode()),
        }
    }

    fn handle_backend(&mut self, msg: Message, out: &mut Batch) {
        // While suppressing, everything is dropped until the cycle ends.
        if self.suppressing {
            if msg.tag == protocol::B_READY_FOR_QUERY {
                self.suppressing = false;
                return out.client(msg.encode());
            }
            return;
        }

        match msg.tag {
            protocol::B_ROW_DESCRIPTION => self.handle_row_description(msg, out),
            protocol::B_DATA_ROW => self.handle_data_row(msg, out),

            // The other path that emits rows with no RowDescription. Unrecoverable
            // mid-stream, so the connection goes down rather than the data out.
            protocol::B_COPY_OUT_RESPONSE | protocol::B_COPY_BOTH_RESPONSE => {
                self.rejected_result_sets += 1;
                let err = protocol::build_error(
                    protocol::SQLSTATE_INSUFFICIENT_PRIVILEGE,
                    "pgmask: COPY ... TO is not permitted",
                    Some(
                        "COPY streams rows with no RowDescription, so they cannot be masked. \
                          Use a SELECT.",
                    ),
                );
                {
                    out.client(err.encode());
                    out.close = true;
                }
            }

            // Error DETAIL/HINT can echo column values verbatim.
            protocol::B_ERROR_RESPONSE | protocol::B_NOTICE_RESPONSE => {
                match protocol::scrub_error(&msg.body) {
                    Some(scrubbed) => out.client(Message::new(msg.tag, scrubbed).encode()),
                    None => out.client(msg.encode()),
                }
            }

            // No result set for this Describe; consume its slot.
            b'n' => {
                self.pending_describes.pop_front();
                out.client(msg.encode())
            }

            _ => out.client(msg.encode()),
        }
    }

    fn handle_row_description(&mut self, msg: Message, out: &mut Batch) {
        let fields = match protocol::parse_row_description(&msg.body) {
            Ok(fields) => fields,
            Err(err) => {
                return self.reject(
                    Rejection {
                        message: format!("pgmask: could not parse RowDescription: {err}"),
                        hint: None,
                    },
                    out,
                )
            }
        };

        let plan = match self.policy.plan_for(&fields) {
            Ok(plan) => plan,
            Err(rejection) => {
                self.pending_describes.pop_front();
                return self.reject(rejection, out);
            }
        };

        // Bind the plan to whatever this RowDescription answers, and make it
        // active — which also covers pipelined Bind-before-Describe ordering.
        match self.pending_describes.pop_front() {
            Some(DescribeTarget::Statement(name)) => {
                self.statement_plans.insert(name, plan.clone());
            }
            Some(DescribeTarget::Portal(name)) => {
                self.portal_plans.insert(name, plan.clone());
            }
            None => {}
        }
        self.active_plan = Some(plan);
        out.client(msg.encode())
    }

    fn handle_data_row(&mut self, msg: Message, out: &mut Batch) {
        let Some(plan) = self.active_plan.clone() else {
            // Rows we were never given the shape of. Refuse rather than guess.
            return self.reject(
                Rejection {
                    message: "pgmask: received a data row with no described result set".into(),
                    hint: Some(
                        "The statement produced rows without a RowDescription, so no masking plan \
                     could be built."
                            .into(),
                    ),
                },
                out,
            );
        };

        let values = match protocol::parse_data_row(&msg.body) {
            Ok(values) => values,
            Err(err) => {
                return self.reject(
                    Rejection {
                        message: format!("pgmask: could not parse DataRow: {err}"),
                        hint: None,
                    },
                    out,
                )
            }
        };

        if values.len() != plan.len() {
            return self.reject(
                Rejection {
                    message: format!(
                        "pgmask: row has {} fields but the described result set has {}",
                        values.len(),
                        plan.len()
                    ),
                    hint: None,
                },
                out,
            );
        }

        let mut masked = Vec::with_capacity(values.len());
        let mut changed = false;
        for (value, field) in values.into_iter().zip(plan.iter()) {
            if field.mask == Mask::None {
                masked.push(value);
                continue;
            }
            match self.policy.masker.apply(field.mask, field.type_oid, value) {
                Ok(new_value) => {
                    changed = true;
                    self.masked_fields += 1;
                    masked.push(new_value);
                }
                Err(err) => {
                    return self.reject(
                        Rejection {
                            message: format!("pgmask: {err}"),
                            hint: None,
                        },
                        out,
                    )
                }
            }
        }

        if !changed {
            return out.client(msg.encode());
        }
        out.client(protocol::build_data_row(&masked).encode())
    }
}

/// Startup negotiation, then the message pump.
pub async fn handle_connection(
    client: TcpStream,
    backend_addr: &str,
    policy: Arc<Policy>,
) -> Result<()> {
    client.set_nodelay(true).ok();
    let (client_read, mut client_write) = client.into_split();
    let mut client_frames = FrameReader::new(client_read);

    // --- Startup ------------------------------------------------------------
    // TLS is out of scope for the MVP: answer SSLRequest with 'N' so clients
    // using sslmode=prefer fall back to plaintext.
    let startup = loop {
        let Some(packet) = client_frames.read_startup().await? else {
            return Ok(());
        };
        match packet.code {
            protocol::SSL_REQUEST_CODE | protocol::GSSENC_REQUEST_CODE => {
                client_write.write_all(b"N").await?;
            }
            _ => break packet,
        }
    };

    let backend = TcpStream::connect(backend_addr)
        .await
        .with_context(|| format!("connecting to backend {backend_addr}"))?;
    backend.set_nodelay(true).ok();
    let (backend_read, mut backend_write) = backend.into_split();
    let mut backend_frames = FrameReader::new(backend_read);

    backend_write.write_all(&startup.encode()).await?;
    backend_write.flush().await?;

    // A CancelRequest is its own short-lived connection: forward and hang up.
    if startup.code == protocol::CANCEL_REQUEST_CODE {
        return Ok(());
    }

    let user = startup
        .parameters()
        .into_iter()
        .find(|(k, _)| k == "user")
        .map(|(_, v)| v)
        .unwrap_or_else(|| "<unknown>".into());

    // --- Message pump -------------------------------------------------------
    let mut session = Session::new(policy);
    let mut authenticated = false;

    // Accumulate a whole batch before touching the sockets. One `read_buf`
    // typically carries hundreds of DataRows; flushing per message turned that
    // into a syscall per row and dominated bulk throughput.
    let mut out = Batch::default();

    'pump: loop {
        tokio::select! {
            msg = client_frames.read_message() => match msg? {
                Some(msg) => {
                    session.handle_frontend(msg, &mut out);
                    // Drain whatever else arrived in the same read.
                    while let Some(msg) = client_frames.try_buffered_message()? {
                        session.handle_frontend(msg, &mut out);
                    }
                }
                None => break 'pump,
            },
            msg = backend_frames.read_message() => match msg? {
                Some(msg) => {
                    // Postgres just vouched for the username; only now is it
                    // safe to treat as verified identity.
                    if !authenticated
                        && msg.tag == protocol::B_AUTHENTICATION
                        && msg.body.len() >= 4
                        && i32::from_be_bytes([msg.body[0], msg.body[1], msg.body[2], msg.body[3]]) == 0
                    {
                        authenticated = true;
                    }
                    session.handle_backend(msg, &mut out);
                    while let Some(msg) = backend_frames.try_buffered_message()? {
                        session.handle_backend(msg, &mut out);
                    }
                }
                None => break 'pump,
            },
        }

        if !out.is_empty() {
            if !out.to_backend.is_empty() {
                backend_write.write_all(&out.to_backend).await?;
                backend_write.flush().await?;
                out.to_backend.clear();
            }
            if !out.to_client.is_empty() {
                client_write.write_all(&out.to_client).await?;
                client_write.flush().await?;
                out.to_client.clear();
            }
        }
        if out.close {
            break;
        }
    }

    if session.masked_fields > 0 || session.rejected_result_sets > 0 {
        eprintln!(
            "session closed user={user} authenticated={authenticated} \
             masked_fields={} rejected_result_sets={}",
            session.masked_fields, session.rejected_result_sets
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::FieldDescription;

    fn policy(unclassified: Unclassified, opaque: Opaque) -> Arc<Policy> {
        Arc::new(Policy {
            catalog: Arc::new(Catalog::default()),
            masker: Arc::new(Masker::new(b"k".to_vec())),
            unclassified,
            unclassified_mask: Mask::Null,
            opaque,
        })
    }

    fn field(name: &str, table_oid: u32, column_id: i16, type_oid: u32) -> FieldDescription {
        FieldDescription {
            name: name.into(),
            table_oid,
            column_id,
            type_oid,
            format: 0,
        }
    }

    #[test]
    fn opaque_field_is_rejected_by_default() {
        let p = policy(Unclassified::Allow, Opaque::Reject);
        let err = p
            .plan_for(&[field("lower", 0, 0, 25)])
            .expect_err("must reject");
        assert!(err.message.contains("no column provenance"));
    }

    #[test]
    fn opaque_field_can_be_masked_instead() {
        let p = policy(Unclassified::Allow, Opaque::Mask);
        let plan = p
            .plan_for(&[field("lower", 0, 0, 25)])
            .ok()
            .expect("must allow");
        assert_eq!(plan[0].mask, Mask::Null);
    }

    #[test]
    fn unclassified_columns_are_masked_by_default() {
        let p = policy(Unclassified::Mask, Opaque::Reject);
        let plan = p.plan_for(&[field("email", 16391, 2, 25)]).ok().unwrap();
        assert_eq!(plan[0].mask, Mask::Null, "default-deny");
    }

    #[test]
    fn allow_mode_passes_unclassified_columns() {
        let p = policy(Unclassified::Allow, Opaque::Reject);
        let plan = p.plan_for(&[field("email", 16391, 2, 25)]).ok().unwrap();
        assert_eq!(plan[0].mask, Mask::None);
    }

    #[test]
    fn text_mask_on_a_non_text_column_is_refused_at_plan_time() {
        let mut catalog = Catalog::default();
        catalog.insert_for_test(16391, 1, Mask::Pseudonym, "demo.t.id");
        let p = Arc::new(Policy {
            catalog: Arc::new(catalog),
            masker: Arc::new(Masker::new(b"k".to_vec())),
            unclassified: Unclassified::Allow,
            unclassified_mask: Mask::Null,
            opaque: Opaque::Reject,
        });
        // int4, not a text type.
        let err = p
            .plan_for(&[field("id", 16391, 1, 23)])
            .expect_err("must reject");
        assert!(err.message.contains("not a text type"));
    }

    #[test]
    fn a_data_row_with_no_plan_is_never_forwarded() {
        let mut session = Session::new(policy(Unclassified::Allow, Opaque::Reject));
        let row = protocol::build_data_row(&[Some(Bytes::from_static(b"alice@example.com"))]);
        let mut out = Batch::default();
        session.handle_data_row(row, &mut out);
        assert!(!out.to_client.is_empty());
        let text = String::from_utf8_lossy(&out.to_client).to_string();
        assert!(
            !text.contains("alice@example.com"),
            "leaked an unmasked value"
        );
        assert!(text.contains("no described result set"));
        assert!(
            session.suppressing,
            "must swallow the rest of the result set"
        );
    }

    #[test]
    fn suppression_swallows_rows_and_releases_on_ready_for_query() {
        let mut session = Session::new(policy(Unclassified::Allow, Opaque::Reject));
        session.suppressing = true;

        let row = protocol::build_data_row(&[Some(Bytes::from_static(b"secret"))]);
        let mut out = Batch::default();
        session.handle_backend(row, &mut out);
        assert!(out.to_client.is_empty());

        let ready = Message::new(protocol::B_READY_FOR_QUERY, Bytes::from_static(b"I"));
        let mut out = Batch::default();
        session.handle_backend(ready, &mut out);
        assert!(!out.to_client.is_empty());
        assert!(!session.suppressing);
    }

    #[test]
    fn copy_out_is_refused_and_closes_the_connection() {
        let mut session = Session::new(policy(Unclassified::Allow, Opaque::Reject));
        let copy = Message::new(
            protocol::B_COPY_OUT_RESPONSE,
            Bytes::from_static(&[0, 0, 0]),
        );
        let mut out = Batch::default();
        session.handle_backend(copy, &mut out);
        assert!(out.close);
        assert!(String::from_utf8_lossy(&out.to_client).contains("COPY"));
    }

    #[test]
    fn function_call_is_refused() {
        let mut session = Session::new(policy(Unclassified::Allow, Opaque::Reject));
        let msg = Message::new(protocol::F_FUNCTION_CALL, Bytes::from_static(b""));
        let mut out = Batch::default();
        session.handle_frontend(msg, &mut out);
        assert!(out.close);
        assert!(out.to_backend.is_empty(), "must never reach the backend");
    }

    #[test]
    fn a_simple_query_invalidates_the_previous_plan() {
        let mut session = Session::new(policy(Unclassified::Allow, Opaque::Reject));
        session.active_plan = Some(Arc::new(vec![FieldPlan {
            mask: Mask::None,
            type_oid: 25,
        }]));
        let query = Message::new(protocol::F_QUERY, Bytes::from_static(b"SELECT 1\0"));
        session.handle_frontend(query, &mut Batch::default());
        assert!(
            session.active_plan.is_none(),
            "stale plans must not survive a new query"
        );
    }

    #[test]
    fn bind_carries_the_statement_plan_to_the_portal() {
        let mut session = Session::new(policy(Unclassified::Allow, Opaque::Reject));
        let plan: Plan = Arc::new(vec![FieldPlan {
            mask: Mask::None,
            type_oid: 25,
        }]);
        session.statement_plans.insert("s1".into(), plan);

        let mut body = bytes::BytesMut::new();
        bytes::BufMut::put_slice(&mut body, b"p1\0s1\0");
        session.handle_frontend(
            Message::new(protocol::F_BIND, body.freeze()),
            &mut Batch::default(),
        );
        assert!(session.portal_plans.contains_key("p1"));

        let mut exec = bytes::BytesMut::new();
        bytes::BufMut::put_slice(&mut exec, b"p1\0");
        bytes::BufMut::put_i32(&mut exec, 0);
        session.handle_frontend(
            Message::new(protocol::F_EXECUTE, exec.freeze()),
            &mut Batch::default(),
        );
        assert!(
            session.active_plan.is_some(),
            "re-executing a prepared statement must work"
        );
    }

    #[test]
    fn binding_an_undescribed_statement_leaves_no_plan() {
        let mut session = Session::new(policy(Unclassified::Allow, Opaque::Reject));
        let mut body = bytes::BytesMut::new();
        bytes::BufMut::put_slice(&mut body, b"p1\0unknown\0");
        session.handle_frontend(
            Message::new(protocol::F_BIND, body.freeze()),
            &mut Batch::default(),
        );

        let mut exec = bytes::BytesMut::new();
        bytes::BufMut::put_slice(&mut exec, b"p1\0");
        bytes::BufMut::put_i32(&mut exec, 0);
        session.handle_frontend(
            Message::new(protocol::F_EXECUTE, exec.freeze()),
            &mut Batch::default(),
        );
        assert!(session.active_plan.is_none(), "fail closed");
    }
}
