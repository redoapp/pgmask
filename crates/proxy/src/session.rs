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

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::analysis::{self, Safety};
use crate::catalog::{Catalog, Config, Opaque, Summaries, SystemCatalogs, Unclassified};
use crate::mask::{Mask, MaskSpec, Masker};
use crate::metrics::{Cause, Metrics};
use crate::protocol::{self, DescribeTarget, FrameReader, Message};
use crate::tls::{BackendTls, BoxStream};

/// What to do with one output field.
#[derive(Debug, Clone)]
struct FieldPlan {
    spec: MaskSpec,
    type_oid: u32,
    format: i16,
}

type Plan = Arc<Vec<FieldPlan>>;

/// Why a result set was refused: the words the client sees, plus the bucket the
/// counters see.
struct Rejection {
    message: String,
    hint: Option<String>,
    cause: Cause,
}

pub struct Policy {
    pub catalog: Arc<Catalog>,
    pub masker: Arc<Masker>,
    pub unclassified: Unclassified,
    pub unclassified_mask: Mask,
    pub opaque: Opaque,
    pub metrics: Arc<Metrics>,
    pub summaries: Summaries,
    pub system_catalogs: SystemCatalogs,
    /// Principal -> roles, from `[[role]]`.
    pub roles: HashMap<String, HashSet<String>>,
    /// Present when `tls_cert`/`tls_key` are configured. Absent means we answer
    /// `SSLRequest` with `N` and clients using `sslmode=prefer` fall back.
    pub tls: Option<tokio_rustls::TlsAcceptor>,
    pub backend_tls: BackendTls,
}

impl Policy {
    pub fn from_config(config: &Config, catalog: Arc<Catalog>) -> Result<Self> {
        let tls = match (&config.tls_cert, &config.tls_key) {
            (Some(cert), Some(key)) => Some(crate::tls::load_acceptor(cert, key)?),
            (None, None) => None,
            _ => anyhow::bail!("tls_cert and tls_key must be set together"),
        };
        Ok(Self {
            catalog,
            masker: Arc::new(Masker::new(config.pseudonym_key.clone().into_bytes())),
            unclassified: config.unclassified,
            unclassified_mask: config.unclassified_mask,
            opaque: config.opaque,
            metrics: Arc::new(Metrics::default()),
            summaries: config.summaries,
            system_catalogs: config.system_catalogs,
            roles: roles_by_principal(&config.role),
            tls,
            backend_tls: config.backend_tls,
        })
    }

    /// Roles held by a verified principal.
    pub fn roles_of(&self, principal: &str) -> HashSet<String> {
        self.roles.get(principal).cloned().unwrap_or_default()
    }

    /// Decide the plan for a described result set, or refuse it.
    ///
    /// Takes the principal's roles because the same column can resolve to
    /// different masks for different people — so a plan is only ever valid for
    /// the session that built it.
    fn plan_for(
        &self,
        fields: &[protocol::FieldDescription],
        roles: &HashSet<String>,
        safety: &[Safety],
    ) -> Result<Plan, Rejection> {
        let snapshot = self.catalog.snapshot();
        let mut plan = Vec::with_capacity(fields.len());
        for (index, field) in fields.iter().enumerate() {
            let provably_safe = safety.get(index).copied() == Some(Safety::Releasable);
            let spec = if !field.has_provenance() {
                // An expression we positively identified as carrying no column
                // value — `SELECT 1`, `now()`, `count(*)`. Passing it through is
                // the point of the analysis; see analysis.rs for why the rule is
                // an allowlist of shapes rather than a search for column refs.
                if provably_safe {
                    self.metrics.record_rescued();
                    MaskSpec::new(Mask::None)
                } else {
                    match self.opaque {
                        Opaque::Reject => {
                            return Err(Rejection {
                                cause: Cause::classify_opaque(&field.name, &snapshot),
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
                        Opaque::Mask => MaskSpec::new(Mask::Null),
                    }
                }
            } else {
                match snapshot.lookup(field.table_oid, field.column_id) {
                    Some(classification) => classification.for_roles(roles).clone(),
                    None => {
                        // A relation we have never resolved may mean the catalog
                        // has gone stale — a recreated view gets a new OID. Nudge
                        // the refresher; it enforces its own rate floor.
                        if !snapshot.knows_relation(field.table_oid) {
                            self.catalog.note_unknown_relation();
                        }
                        MaskSpec::new(match self.unclassified {
                            Unclassified::Mask => self.unclassified_mask,
                            Unclassified::Allow => Mask::None,
                        })
                    }
                }
            };

            // Catch type/format mismatches once here rather than per row, so a
            // misconfiguration refuses the result set instead of dying halfway
            // through a stream.
            if !spec.supports(field.type_oid, field.format) {
                let name = snapshot
                    .name_of(field.table_oid, field.column_id)
                    .unwrap_or(&field.name)
                    .to_string();
                return Err(Rejection {
                    cause: Cause::MaskTypeMismatch,
                    message: format!(
                        "pgmask: mask {:?} on {name} cannot be applied to type OID {} in {} \
                         format",
                        spec.kind,
                        field.type_oid,
                        if field.format == 1 { "binary" } else { "text" },
                    ),
                    hint: Some(spec.unsupported_hint().into()),
                });
            }

            plan.push(FieldPlan {
                spec,
                type_oid: field.type_oid,
                format: field.format,
            });
        }
        Ok(Arc::new(plan))
    }
}

/// Invert `[[role]]` declarations into principal -> roles.
fn roles_by_principal(roles: &[crate::catalog::Role]) -> HashMap<String, HashSet<String>> {
    let mut out: HashMap<String, HashSet<String>> = HashMap::new();
    for role in roles {
        for member in &role.members {
            out.entry(member.clone())
                .or_default()
                .insert(role.name.clone());
        }
    }
    out
}

/// Bytes cleared for the client.
///
/// The core invariant of this proxy is "no row reaches the client without
/// passing through a masking plan". That was previously enforced by discipline
/// inside `handle_data_row`. It is now enforced by the compiler: `Batch::client`
/// accepts only a `Vetted`, and the constructors below are the complete list of
/// ways to make one. Adding a new "just forward it" path is a type error, not a
/// code-review question.
///
/// The module boundary is load-bearing — the field is private, so nothing
/// outside this file can mint one.
pub struct Vetted(Bytes);

impl Vetted {
    /// A message whose bytes originated with the backend and carry no row data.
    ///
    /// Correct for control and metadata messages. Never correct for `DataRow`,
    /// and `vet_data_row` is the only way to clear one of those.
    fn control(msg: &Message) -> Self {
        debug_assert_ne!(
            msg.tag,
            protocol::B_DATA_ROW,
            "DataRow must go through vet_data_row"
        );
        Self(msg.encode())
    }

    /// A row whose every field was run through the active plan.
    fn data_row(values: &[Option<Bytes>]) -> Self {
        Self(protocol::build_data_row(values).encode())
    }

    /// A row we are forwarding unchanged because the plan masks nothing in it.
    ///
    /// Takes the plan to make the claim checkable rather than assumed.
    fn unmasked_row(msg: &Message, plan: &[FieldPlan]) -> Self {
        debug_assert!(
            plan.iter().all(|f| f.spec.is_passthrough()),
            "unmasked_row called with a plan that masks something"
        );
        Self(msg.encode())
    }

    /// A message pgmask generated itself: errors, notices we rebuilt.
    fn synthetic(msg: &Message) -> Self {
        Self(msg.encode())
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
    /// The only way bytes reach the client.
    fn client(&mut self, vetted: Vetted) {
        self.to_client.put_slice(&vetted.0);
    }
    /// The backend direction needs no vetting: it carries queries, not results.
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
    /// SQL text per prepared statement, so the analysis can run when the result
    /// set is described. Bounded by how many statements a client prepares.
    statement_sql: HashMap<String, String>,
    /// Portal -> statement, so an `Execute` can find its SQL.
    portal_statement: HashMap<String, String>,
    /// SQL of the most recent simple query.
    simple_sql: Option<String>,
    /// The SQL the next `RowDescription` belongs to.
    described_sql: Option<String>,
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
    /// Whether this client connection is itself TLS. Decides whether channel
    /// binding is even in play.
    client_tls: bool,
    /// Roles held by the verified principal. Empty until `AuthenticationOk`, so
    /// an unauthenticated session can only ever get the default (most
    /// restrictive) classification.
    roles: HashSet<String>,
    /// The username from `StartupMessage`. Claimed until Postgres vouches.
    principal: String,
    pub authenticated: bool,
}

impl Session {
    pub fn new(policy: Arc<Policy>) -> Self {
        Self {
            policy,
            statement_plans: HashMap::new(),
            statement_sql: HashMap::new(),
            portal_statement: HashMap::new(),
            simple_sql: None,
            described_sql: None,
            portal_plans: HashMap::new(),
            active_plan: None,
            pending_describes: VecDeque::new(),
            suppressing: false,
            masked_fields: 0,
            rejected_result_sets: 0,
            client_tls: false,
            roles: HashSet::new(),
            principal: String::new(),
            authenticated: false,
        }
    }

    /// The username the client claimed at startup. Not trusted until
    /// `AuthenticationOk`; see `note_backend_auth`.
    pub fn with_principal(mut self, principal: &str) -> Self {
        self.principal = principal.to_string();
        self
    }

    /// Postgres has vouched for the username — only now may it select a policy.
    ///
    /// This lives in `handle_backend` rather than in the pump loop because the
    /// pump drains several messages per read, and `AuthenticationOk` usually
    /// arrives in the same TCP segment as the SASL final message. Detecting it
    /// only on the first message of a read silently skipped it, so every session
    /// ran with no roles. Same shape as the CopyData bug: logic in the outer
    /// read that the drain loop never saw.
    fn note_backend_auth(&mut self, msg: &Message) {
        if self.authenticated
            || msg.tag != protocol::B_AUTHENTICATION
            || msg.body.len() < 4
            || i32::from_be_bytes([msg.body[0], msg.body[1], msg.body[2], msg.body[3]]) != 0
        {
            return;
        }
        self.authenticated = true;
        self.roles = self.policy.roles_of(&self.principal);
    }

    pub fn with_client_tls(mut self, client_tls: bool) -> Self {
        self.client_tls = client_tls;
        self
    }

    /// Refuse the in-flight result set: tell the client, swallow the backend's
    /// rows, and let the real `ReadyForQuery` through so transaction state stays
    /// consistent.
    fn reject(&mut self, rejection: Rejection, out: &mut Batch) {
        self.suppressing = true;
        self.active_plan = None;
        self.rejected_result_sets += 1;
        self.policy.metrics.record(rejection.cause);
        let err = protocol::build_error(
            protocol::SQLSTATE_INSUFFICIENT_PRIVILEGE,
            &rejection.message,
            rejection.hint.as_deref(),
        );
        out.client(Vetted::synthetic(&err));
    }

    fn handle_frontend(&mut self, msg: Message, out: &mut Batch) {
        match msg.tag {
            // Emits rows with no RowDescription. One of exactly two such paths.
            protocol::F_FUNCTION_CALL => {
                self.policy.metrics.record(Cause::FunctionCallMessage);
                let err = protocol::build_error(
                    protocol::SQLSTATE_INSUFFICIENT_PRIVILEGE,
                    "pgmask: the legacy FunctionCall protocol message is not permitted",
                    Some("It returns data without a RowDescription, so it cannot be masked."),
                );
                {
                    out.client(Vetted::synthetic(&err));
                    out.close = true;
                }
            }

            // A new simple query invalidates everything: if the backend does not
            // describe the next result set, we must not mask it with a stale plan.
            protocol::F_QUERY => {
                self.active_plan = None;
                self.pending_describes.clear();
                self.simple_sql = protocol::parse_simple_query(&msg.body);
                self.described_sql = self.simple_sql.clone();
                out.backend(msg.encode())
            }

            protocol::F_PARSE => {
                if let Some((name, sql)) = protocol::parse_parse(&msg.body) {
                    self.statement_sql.insert(name, sql);
                }
                out.backend(msg.encode())
            }

            protocol::F_BIND => {
                if let Some((portal, statement)) = protocol::parse_bind(&msg.body) {
                    self.portal_statement
                        .insert(portal.clone(), statement.clone());
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
                    // Remember which statement's SQL the coming RowDescription
                    // belongs to, so the analysis looks at the right text.
                    self.described_sql = match &target {
                        DescribeTarget::Statement(name) => self.statement_sql.get(name).cloned(),
                        DescribeTarget::Portal(portal) => self
                            .portal_statement
                            .get(portal)
                            .and_then(|stmt| self.statement_sql.get(stmt))
                            .cloned(),
                    };
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
        self.note_backend_auth(&msg);

        // While suppressing, everything is dropped until the cycle ends.
        if self.suppressing {
            if msg.tag == protocol::B_READY_FOR_QUERY {
                self.suppressing = false;
                return out.client(Vetted::control(&msg));
            }
            return;
        }

        match msg.tag {
            // A plaintext client cannot be offered channel binding at all:
            // libpq aborts with "server offered SCRAM-SHA-256-PLUS
            // authentication over a non-SSL connection" rather than falling
            // back. Strip it, and the client sends the gs2 flag `n`, which the
            // server accepts. This is what makes pgmask usable in front of a
            // TLS-only managed Postgres such as Neon.
            protocol::B_AUTHENTICATION
                if !self.client_tls
                    && protocol::sasl_mechanisms(&msg.body)
                        .iter()
                        .any(|m| m.ends_with("-PLUS")) =>
            {
                match protocol::strip_channel_binding(&msg.body) {
                    Some(filtered) if protocol::sasl_mechanisms(&filtered).is_empty() => {
                        self.policy.metrics.record(Cause::ChannelBinding);
                        let err = protocol::build_error(
                            protocol::SQLSTATE_INSUFFICIENT_PRIVILEGE,
                            "pgmask: the server offers only channel-binding SASL mechanisms",
                            Some("Enable plain SCRAM-SHA-256 on the server."),
                        );
                        out.client(Vetted::synthetic(&err));
                        out.close = true;
                    }
                    Some(filtered) => {
                        out.client(Vetted::synthetic(&Message::new(msg.tag, filtered)));
                    }
                    None => out.client(Vetted::control(&msg)),
                }
            }

            // With TLS on both legs there is no fix: stripping makes the client
            // send `y`, which the server correctly reads as a downgrade attack.
            // Say so plainly rather than letting the client hit an opaque
            // protocol error that gives no hint about the proxy in the middle.
            protocol::B_AUTHENTICATION
                if self.client_tls
                    && protocol::sasl_mechanisms(&msg.body)
                        .iter()
                        .any(|m| m.ends_with("-PLUS")) =>
            {
                self.policy.metrics.record(Cause::ChannelBinding);
                let err = protocol::build_error(
                    protocol::SQLSTATE_INSUFFICIENT_PRIVILEGE,
                    "pgmask: the server offers SCRAM channel binding, which cannot work \
                     through a proxy that terminates TLS",
                    Some(
                        "Set backend_tls = \"disable\" so Postgres advertises plain \
                         SCRAM-SHA-256, and place pgmask on a trusted segment next to the \
                         database. See protocol::sasl_mechanisms for why stripping the \
                         mechanism does not work.",
                    ),
                );
                out.client(Vetted::synthetic(&err));
                out.close = true;
            }

            protocol::B_ROW_DESCRIPTION => self.handle_row_description(msg, out),
            protocol::B_DATA_ROW => self.handle_data_row(msg, out),

            // The other path that emits rows with no RowDescription. Unrecoverable
            // mid-stream, so the connection goes down rather than the data out.
            protocol::B_COPY_OUT_RESPONSE | protocol::B_COPY_BOTH_RESPONSE => {
                self.rejected_result_sets += 1;
                self.policy.metrics.record(Cause::CopyStream);
                let err = protocol::build_error(
                    protocol::SQLSTATE_INSUFFICIENT_PRIVILEGE,
                    "pgmask: COPY ... TO is not permitted",
                    Some(
                        "COPY streams rows with no RowDescription, so they cannot be masked. \
                          Use a SELECT.",
                    ),
                );
                {
                    out.client(Vetted::synthetic(&err));
                    out.close = true;
                }
            }

            // Error DETAIL/HINT can echo column values verbatim.
            protocol::B_ERROR_RESPONSE | protocol::B_NOTICE_RESPONSE => {
                match protocol::scrub_error(&msg.body) {
                    Some(scrubbed) => {
                        out.client(Vetted::synthetic(&Message::new(msg.tag, scrubbed)))
                    }
                    None => out.client(Vetted::control(&msg)),
                }
            }

            // No result set for this Describe; consume its slot.
            b'n' => {
                self.pending_describes.pop_front();
                out.client(Vetted::control(&msg))
            }

            // Copy-stream payload. Reachable only if a CopyOutResponse slipped
            // past, but this is the byte-carrying message, so it is denied on
            // its own account rather than trusting the earlier check.
            protocol::B_COPY_DATA | protocol::B_COPY_DONE => {
                self.rejected_result_sets += 1;
                self.policy.metrics.record(Cause::CopyStream);
                let err = protocol::build_error(
                    protocol::SQLSTATE_INSUFFICIENT_PRIVILEGE,
                    "pgmask: COPY data stream is not permitted",
                    None,
                );
                out.client(Vetted::synthetic(&err));
                out.close = true;
            }

            // Explicit allowlist. The backend direction gets no catch-all: an
            // unrecognised message might carry row data, and forwarding it
            // because we do not know what it is inverts the whole design.
            //
            // Found by the canary test — CopyData was being forwarded through a
            // `_ =>` arm that existed only because it seemed harmless.
            tag if protocol::BACKEND_CONTROL_TAGS.contains(&tag) => {
                out.client(Vetted::control(&msg))
            }

            unknown => {
                self.rejected_result_sets += 1;
                self.policy.metrics.record(Cause::UnknownBackendMessage);
                let err = protocol::build_error(
                    protocol::SQLSTATE_INSUFFICIENT_PRIVILEGE,
                    &format!(
                        "pgmask: refusing to forward unrecognised backend message '{}'",
                        unknown as char
                    ),
                    Some("pgmask fails closed on protocol messages it cannot classify."),
                );
                out.client(Vetted::synthetic(&err));
                out.close = true;
            }
        }
    }

    fn handle_row_description(&mut self, msg: Message, out: &mut Batch) {
        let fields = match protocol::parse_row_description(&msg.body) {
            Ok(fields) => fields,
            Err(err) => {
                return self.reject(
                    Rejection {
                        cause: Cause::Malformed,
                        message: format!("pgmask: could not parse RowDescription: {err}"),
                        hint: None,
                    },
                    out,
                )
            }
        };

        // Only consulted for fields with no provenance, and only ever able to
        // turn a refusal into a passthrough for a positively-identified shape.
        // A statement that reads only metadata-only system catalogs carries
        // nothing from a user table, so every field is released — including the
        // ones that DO have provenance, which point at catalog relations no
        // catalog file lists and which default-deny would otherwise null. That
        // nulling is what breaks `\d`: psql feeds the OID from one query into
        // the next and gets `invalid input syntax for type oid: ""`.
        let system_catalog = self.policy.system_catalogs == SystemCatalogs::Allow
            && self
                .described_sql
                .as_deref()
                .is_some_and(analysis::reads_only_server_metadata);

        let safety = match &self.described_sql {
            Some(sql) => {
                analysis::analyze(sql, fields.len(), self.policy.summaries == Summaries::Allow)
            }
            None => vec![Safety::Unknown; fields.len()],
        };
        let planned = if system_catalog {
            Ok(Arc::new(
                fields
                    .iter()
                    .map(|field| FieldPlan {
                        spec: MaskSpec::new(Mask::None),
                        type_oid: field.type_oid,
                        format: field.format,
                    })
                    .collect::<Vec<_>>(),
            ))
        } else {
            self.policy.plan_for(&fields, &self.roles, &safety)
        };
        let plan = match planned {
            Ok(plan) => plan,
            Err(rejection) => {
                self.pending_describes.pop_front();
                return self.reject(rejection, out);
            }
        };

        // Successful result sets are the denominator: a rejection share is
        // meaningless without knowing how much traffic sails through.
        let masking = plan.iter().filter(|f| !f.spec.is_passthrough()).count();
        if masking > 0 {
            self.policy.metrics.record_masked_result_set(masking as u64);
        }

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
        out.client(Vetted::control(&msg))
    }

    fn handle_data_row(&mut self, msg: Message, out: &mut Batch) {
        let Some(plan) = self.active_plan.clone() else {
            // Rows we were never given the shape of. Refuse rather than guess.
            return self.reject(
                Rejection {
                    cause: Cause::NoActivePlan,
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
                        cause: Cause::Malformed,
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
                    cause: Cause::Malformed,
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
            if field.spec.is_passthrough() {
                masked.push(value);
                continue;
            }
            match self
                .policy
                .masker
                .apply(&field.spec, field.type_oid, field.format, value)
            {
                Ok(new_value) => {
                    changed = true;
                    self.masked_fields += 1;
                    masked.push(new_value);
                }
                Err(err) => {
                    return self.reject(
                        Rejection {
                            cause: Cause::MaskTypeMismatch,
                            message: format!("pgmask: {err}"),
                            hint: None,
                        },
                        out,
                    )
                }
            }
        }

        if !changed {
            return out.client(Vetted::unmasked_row(&msg, &plan));
        }
        out.client(Vetted::data_row(&masked))
    }
}

/// Read one untagged startup packet straight off the socket.
///
/// Startup cannot go through `FrameReader`, because answering `SSLRequest`
/// means replacing the whole stream with a TLS session — a buffered reader that
/// already owned the socket would strand any bytes it had read ahead. Clients
/// wait for the single-byte reply before sending anything more, so reading
/// exactly one packet at a time here is safe.
async fn read_startup_packet<S: AsyncReadExt + Unpin>(
    stream: &mut S,
) -> Result<Option<protocol::StartupPacket>> {
    let mut len_bytes = [0u8; 4];
    match stream.read_exact(&mut len_bytes).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err.into()),
    }
    let len = i32::from_be_bytes(len_bytes);
    if !(8..=1_048_576).contains(&len) {
        anyhow::bail!("implausible startup packet length {len}");
    }
    let mut rest = vec![0u8; len as usize - 4];
    stream.read_exact(&mut rest).await?;
    let code = i32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
    Ok(Some(protocol::StartupPacket {
        code,
        body: Bytes::from(rest).slice(4..),
    }))
}

/// Startup negotiation on both legs, then the message pump.
pub async fn handle_connection(
    client: TcpStream,
    backend_addr: &str,
    policy: Arc<Policy>,
) -> Result<()> {
    client.set_nodelay(true).ok();
    let mut client_stream: BoxStream = Box::new(client);

    // --- Client-side TLS negotiation ----------------------------------------
    // Postgres has no ALPN and no separate TLS port: the client asks with an
    // SSLRequest packet and we answer with one byte before any TLS bytes flow.
    let mut client_tls = false;
    let startup = loop {
        let Some(packet) = read_startup_packet(&mut client_stream).await? else {
            return Ok(());
        };
        match packet.code {
            protocol::SSL_REQUEST_CODE => match policy.tls.clone() {
                Some(acceptor) => {
                    client_stream.write_all(b"S").await?;
                    client_stream.flush().await?;
                    // `TlsAcceptor` needs a concrete stream, and we still hold a
                    // box; downcasting is not available, so the acceptor is
                    // applied to the boxed stream directly.
                    let tls = acceptor
                        .accept(client_stream)
                        .await
                        .context("client TLS handshake failed")?;
                    client_stream = Box::new(tls);
                    client_tls = true;
                }
                None => {
                    client_stream.write_all(b"N").await?;
                    client_stream.flush().await?;
                }
            },
            // We never offer GSSAPI encryption.
            protocol::GSSENC_REQUEST_CODE => {
                client_stream.write_all(b"N").await?;
                client_stream.flush().await?;
            }
            _ => break packet,
        }
    };

    // --- Backend connection -------------------------------------------------
    let backend = TcpStream::connect(backend_addr)
        .await
        .with_context(|| format!("connecting to backend {backend_addr}"))?;
    backend.set_nodelay(true).ok();
    let mut backend_stream: BoxStream = match policy.backend_tls {
        BackendTls::Disable => Box::new(backend),
        BackendTls::Require => {
            // Strip the port: SNI carries a hostname, never host:port.
            let host = backend_addr
                .rsplit_once(':')
                .map_or(backend_addr, |(h, _)| h);
            crate::tls::upgrade_backend(backend, host).await?
        }
    };

    backend_stream.write_all(&startup.encode()).await?;
    backend_stream.flush().await?;

    // A CancelRequest is its own short-lived connection carrying the backend's
    // own key (we forward BackendKeyData verbatim, so the client holds the real
    // one). Forward and hang up.
    if startup.code == protocol::CANCEL_REQUEST_CODE {
        return Ok(());
    }

    let (client_read, mut client_write) = tokio::io::split(client_stream);
    let (backend_read, mut backend_write) = tokio::io::split(backend_stream);
    let mut client_frames = FrameReader::new(client_read);
    let mut backend_frames = FrameReader::new(backend_read);

    let user = startup
        .parameters()
        .into_iter()
        .find(|(k, _)| k == "user")
        .map(|(_, v)| v)
        .unwrap_or_else(|| "<unknown>".into());

    // --- Message pump -------------------------------------------------------
    let mut session = Session::new(policy)
        .with_client_tls(client_tls)
        .with_principal(&user);

    // Accumulate a whole batch before touching the sockets. One `read_buf`
    // typically carries hundreds of DataRows; flushing per message turned that
    // into a syscall per row and dominated bulk throughput.
    let mut out = Batch::default();

    'pump: loop {
        tokio::select! {
            // One `handle_frontend` call site, deliberately. The obvious
            // shape — handle the first message, then loop over the rest — gives
            // each handler *two* call sites, and anything added to only one of
            // them silently applies to a subset of messages. That mistake was
            // made twice here: CopyData escaped through the drain after a
            // refusal, and AuthenticationOk went unseen because it usually
            // shares a TCP segment with the SASL final message, so no session
            // ever resolved a principal. Neither was caught by a type; both were
            // caught by luck. Do not reintroduce the asymmetry.
            msg = client_frames.read_message() => {
                let mut current = msg?;
                while let Some(msg) = current {
                    session.handle_frontend(msg, &mut out);
                    if out.close {
                        break;
                    }
                    current = client_frames.try_buffered_message()?;
                }
                if client_frames.saw_eof() {
                    break 'pump;
                }
            },
            msg = backend_frames.read_message() => {
                let mut current = msg?;
                while let Some(msg) = current {
                    session.handle_backend(msg, &mut out);
                    if out.close {
                        break;
                    }
                    current = backend_frames.try_buffered_message()?;
                }
                if backend_frames.saw_eof() {
                    break 'pump;
                }
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
            "session closed user={user} authenticated={} roles={} \
             masked_fields={} rejected_result_sets={}",
            session.authenticated,
            session.roles.len(),
            session.masked_fields,
            session.rejected_result_sets
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
            metrics: Arc::new(Metrics::default()),
            summaries: Summaries::Allow,
            system_catalogs: SystemCatalogs::Refuse,
            roles: HashMap::new(),
            tls: None,
            backend_tls: BackendTls::Disable,
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
            .plan_for(&[field("lower", 0, 0, 25)], &HashSet::new(), &[])
            .expect_err("must reject");
        assert!(err.message.contains("no column provenance"));
    }

    #[test]
    fn opaque_field_can_be_masked_instead() {
        let p = policy(Unclassified::Allow, Opaque::Mask);
        let plan = p
            .plan_for(&[field("lower", 0, 0, 25)], &HashSet::new(), &[])
            .ok()
            .expect("must allow");
        assert_eq!(plan[0].spec.kind, Mask::Null);
    }

    #[test]
    fn unclassified_columns_are_masked_by_default() {
        let p = policy(Unclassified::Mask, Opaque::Reject);
        let plan = p
            .plan_for(&[field("email", 16391, 2, 25)], &HashSet::new(), &[])
            .ok()
            .unwrap();
        assert_eq!(plan[0].spec.kind, Mask::Null, "default-deny");
    }

    #[test]
    fn allow_mode_passes_unclassified_columns() {
        let p = policy(Unclassified::Allow, Opaque::Reject);
        let plan = p
            .plan_for(&[field("email", 16391, 2, 25)], &HashSet::new(), &[])
            .ok()
            .unwrap();
        assert_eq!(plan[0].spec.kind, Mask::None);
    }

    #[test]
    fn text_mask_on_a_non_text_column_is_refused_at_plan_time() {
        let mut snapshot = crate::catalog::Snapshot::default();
        snapshot.insert_for_test(16391, 1, Mask::Pseudonym, "demo.t.id");
        let p = Arc::new(Policy {
            catalog: Arc::new(Catalog::from_snapshot_for_test(snapshot)),
            masker: Arc::new(Masker::new(b"k".to_vec())),
            unclassified: Unclassified::Allow,
            unclassified_mask: Mask::Null,
            opaque: Opaque::Reject,
            metrics: Arc::new(Metrics::default()),
            summaries: Summaries::Allow,
            system_catalogs: SystemCatalogs::Refuse,
            roles: HashMap::new(),
            tls: None,
            backend_tls: BackendTls::Disable,
        });
        // int4, not a text type: pseudonym rewrites values as text.
        let err = p
            .plan_for(&[field("id", 16391, 1, 23)], &HashSet::new(), &[])
            .expect_err("must reject");
        assert!(
            err.message.contains("cannot be applied to type OID 23"),
            "got: {}",
            err.message
        );
        assert!(
            err.hint.as_deref().unwrap_or("").contains("null"),
            "the hint should say what to do instead"
        );
    }

    #[test]
    fn per_role_masks_resolve_most_restrictive_first() {
        use crate::catalog::{Classification, Role};
        use std::collections::HashMap as Map;

        let mut by_role = Map::new();
        by_role.insert("analyst".to_string(), MaskSpec::new(Mask::Partial));
        by_role.insert("support".to_string(), MaskSpec::new(Mask::Null));
        let classification = Classification {
            default: MaskSpec::new(Mask::Pseudonym),
            by_role,
        };

        // No role: the default.
        assert_eq!(
            classification.for_roles(&HashSet::new()).kind,
            Mask::Pseudonym
        );
        // One role: that role's mask.
        let analyst: HashSet<String> = ["analyst".to_string()].into_iter().collect();
        assert_eq!(classification.for_roles(&analyst).kind, Mask::Partial);
        // Both roles: the tighter one, because adding a role must never widen
        // access.
        let both: HashSet<String> = ["analyst".to_string(), "support".to_string()]
            .into_iter()
            .collect();
        assert_eq!(classification.for_roles(&both).kind, Mask::Null);

        // And principals with no declared role get no roles at all.
        let roles = roles_by_principal(&[Role {
            name: "analyst".into(),
            members: vec!["alice".into()],
        }]);
        assert!(roles.get("alice").unwrap().contains("analyst"));
        assert!(!roles.contains_key("mallory"));
    }

    /// Regression: AuthenticationOk usually shares a TCP segment with the SASL
    /// final message, so it reaches `handle_backend` via the drain loop rather
    /// than as the first message of a read. Detecting it only in the pump meant
    /// no session ever resolved a principal, and every user silently got the
    /// default policy.
    #[test]
    fn authentication_ok_is_detected_even_when_it_is_not_the_first_message() {
        use crate::catalog::Role;

        let mut p = policy(Unclassified::Allow, Opaque::Reject);
        Arc::get_mut(&mut p).unwrap().roles = roles_by_principal(&[Role {
            name: "support".into(),
            members: vec!["sam".into()],
        }]);

        let mut session = Session::new(p).with_principal("sam");
        let mut out = Batch::default();

        // SASLFinal (Authentication sub-code 12) — not AuthenticationOk.
        let mut sasl_final = bytes::BytesMut::new();
        bytes::BufMut::put_i32(&mut sasl_final, 12);
        session.handle_backend(
            Message::new(protocol::B_AUTHENTICATION, sasl_final.freeze()),
            &mut out,
        );
        assert!(!session.authenticated, "12 is not AuthenticationOk");
        assert!(session.roles.is_empty());

        // AuthenticationOk arriving second, as it does on the wire.
        let mut ok = bytes::BytesMut::new();
        bytes::BufMut::put_i32(&mut ok, 0);
        session.handle_backend(
            Message::new(protocol::B_AUTHENTICATION, ok.freeze()),
            &mut out,
        );
        assert!(session.authenticated, "AuthenticationOk must be seen");
        assert!(
            session.roles.contains("support"),
            "the verified principal's roles must be resolved"
        );
    }

    #[test]
    fn an_unclaimed_principal_gets_no_roles() {
        use crate::catalog::Role;
        let mut p = policy(Unclassified::Allow, Opaque::Reject);
        Arc::get_mut(&mut p).unwrap().roles = roles_by_principal(&[Role {
            name: "support".into(),
            members: vec!["sam".into()],
        }]);
        let mut session = Session::new(p).with_principal("mallory");
        let mut ok = bytes::BytesMut::new();
        bytes::BufMut::put_i32(&mut ok, 0);
        session.handle_backend(
            Message::new(protocol::B_AUTHENTICATION, ok.freeze()),
            &mut Batch::default(),
        );
        assert!(session.authenticated);
        assert!(session.roles.is_empty(), "unknown principals get nothing");
    }

    #[test]
    fn an_unauthenticated_session_gets_the_default_classification() {
        // Roles are only ever populated from a username Postgres verified, so a
        // session that never authenticated cannot pick up a looser mask.
        let session = Session::new(policy(Unclassified::Mask, Opaque::Reject));
        assert!(session.roles.is_empty());
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
            spec: MaskSpec::new(Mask::None),
            type_oid: 25,
            format: 0,
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
            spec: MaskSpec::new(Mask::None),
            type_oid: 25,
            format: 0,
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
