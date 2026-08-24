//! Classification policy for described result sets.
//!
//! This module owns the *decision*: given one `RowDescription`'s fields, the
//! current catalog snapshot, the principal's roles, and the statement analysis,
//! what masking plan governs the rows that follow — or why the result set is
//! refused. `session.rs` owns the wire state machine and asks exactly one
//! question of this module per described result set, through
//! [`Policy::plan_for`].
//!
//! The boundary type is [`Rejection`]: the words the client sees plus the
//! bucket the counters see. Everything upstream of a `Rejection` is policy;
//! everything downstream — suppressing the backend's rows, replying with an
//! `ErrorResponse`, keeping the protocol in sync — is the session's problem.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::Result;

use crate::analysis::{self, Safety};
use crate::catalog::{
    Catalog, Config, Lineage, Opaque, Posture, Snapshot, Summaries, SystemCatalogs, Unclassified,
    UnclassifiedMask,
};
use crate::lineage::Verdict;
use crate::mask::{Mask, MaskSpec, Masker};
use crate::metrics::{Cause, Metrics};
use crate::plan_state::{FieldPlan, Plan};
use crate::protocol;
use crate::rate_limit::PrincipalRateLimit;
use crate::tls::BackendTls;
use secrecy::ExposeSecret;

/// Why a result set was refused: the words the client sees, plus the bucket the
/// counters see.
pub(crate) struct Rejection {
    pub(crate) message: String,
    pub(crate) hint: Option<String>,
    pub(crate) cause: Cause,
}

pub struct Policy {
    pub(crate) catalog: Arc<Catalog>,
    pub(crate) masker: Arc<Masker>,
    unclassified: Unclassified,
    unclassified_mask: UnclassifiedMask,
    opaque: Opaque,
    pub(crate) metrics: Arc<Metrics>,
    pub(crate) summaries: Summaries,
    pub(crate) posture: Posture,
    pub(crate) system_catalogs: SystemCatalogs,
    pub(crate) lineage: Lineage,
    /// Principal -> roles, from `[[role]]`.
    pub(crate) roles: HashMap<String, HashSet<String>>,
    /// Present when `tls_cert`/`tls_key` are configured. Absent means we answer
    /// `SSLRequest` with `N` and clients using `sslmode=prefer` fall back.
    pub(crate) tls: Option<tokio_rustls::TlsAcceptor>,
    /// Whether a session that did not negotiate TLS is refused. Resolved from
    /// `Config::client_tls_required`, so the default "a configured certificate
    /// is a required certificate" lives in one place.
    require_client_tls: bool,
    pub(crate) backend_tls: BackendTls,
    pub(crate) backend_ca: Option<String>,
    /// Shared across sessions so one user with many connections shares one
    /// budget. `None` when `rate_limit_per_minute = 0`.
    pub(crate) rate_limit: Option<PrincipalRateLimit>,
    /// `None` when `max_notices_per_exchange = 0` (unlimited).
    pub(crate) max_notices_per_exchange: Option<u32>,
}

/// Everything `Policy::plan_for` needs to classify one result set, grouped so
/// the decision hub stays under the clippy argument budget.
pub(crate) struct FieldAnalysis<'a> {
    /// Per-field analysis verdict (`Summary`, `Releasable`, `Unknown`, …).
    pub safety: &'a [Safety],
    /// Per-field lineage verdict, when lineage ran (`Release`/`Blocked`/…).
    pub lineage: &'a [Verdict],
    /// Per-field reducing-aggregate policy after syntax and catalog resolution.
    pub summary: &'a [SummaryPolicy],
    /// Whether the engine's column provenance is believed (set-op distrust).
    pub trust_provenance: bool,
}

/// The complete policy state for one potential reducing-aggregate field.
///
/// Keeping `Released` distinct from `Masked` prevents a missing attribution
/// (`Opaque`) from being represented as a permissive `None` mask. Keeping
/// `NotApplicable` distinct from `Opaque` makes the safety gate explicit too.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum SummaryPolicy {
    NotApplicable,
    Opaque,
    Released,
    Masked(MaskSpec),
}

impl FieldAnalysis<'_> {
    /// The reducing-aggregate policy for `index`.
    ///
    /// Gated on the field actually being `Safety::Summary`, not merely being an
    /// aggregate-shaped expression: `max(x)` returns a stored value and must
    /// keep falling through to the opaque posture, and it is refused there. Only
    /// the reducing purity-allowlist (which `classify` maps to `Summary`)
    /// reaches a policy here. The source can be masked or explicitly released:
    /// schema qualification removes the `search_path` guess that made
    /// passthrough unsafe in the earlier fallback.
    pub(crate) fn summary_policy_for(&self, index: usize) -> SummaryPolicy {
        if self.safety.get(index) != Some(&Safety::Summary) {
            return SummaryPolicy::NotApplicable;
        }
        self.summary
            .get(index)
            .cloned()
            .unwrap_or(SummaryPolicy::Opaque)
    }
}

impl Policy {
    pub fn from_config(config: &Config, catalog: Arc<Catalog>) -> Result<Self> {
        // `Config` is public because the classifier and test adapters build it
        // programmatically. File loading validates it, but runtime policy must
        // not depend on which construction path the caller used.
        config.validate()?;
        let tls = match (&config.tls_cert, &config.tls_key) {
            (Some(cert), Some(key)) => Some(crate::tls::load_acceptor(cert, key)?),
            (None, None) => None,
            _ => anyhow::bail!("tls_cert and tls_key must be set together"),
        };
        let rate_limit = if config.rate_limit_per_minute > 0 {
            Some(PrincipalRateLimit::new(
                config.rate_limit_per_minute,
                config.effective_rate_limit_burst(),
            )?)
        } else {
            None
        };
        let max_notices_per_exchange = match config.max_notices_per_exchange {
            0 => None,
            n => Some(n),
        };
        Ok(Self {
            catalog,
            masker: Arc::new(Masker::new(
                config.pseudonym_key.expose_secret().as_bytes().to_vec(),
            )),
            unclassified: config.unclassified,
            unclassified_mask: config.unclassified_mask,
            opaque: config.opaque,
            metrics: Arc::new(Metrics::default()),
            summaries: config.effective_summaries(),
            posture: config.posture,
            system_catalogs: config.system_catalogs,
            lineage: config.lineage,
            roles: roles_by_principal(&config.role),
            tls,
            require_client_tls: config.client_tls_required(),
            backend_tls: config.backend_tls,
            backend_ca: config.backend_ca.clone(),
            rate_limit,
            max_notices_per_exchange,
        })
    }

    /// Roles held by a verified principal.
    pub fn roles_of(&self, principal: &str) -> HashSet<String> {
        self.roles.get(principal).cloned().unwrap_or_default()
    }

    pub fn role_count(&self) -> usize {
        self.roles.len()
    }

    /// Whether a certificate is *configured*. Deliberately not named
    /// `has_client_tls`: that reads as a property of the connection, and a
    /// configured certificate says nothing about whether any given client
    /// used it. `Session::client_tls` is the per-connection fact.
    pub fn client_tls_configured(&self) -> bool {
        self.tls.is_some()
    }

    pub fn client_tls_required(&self) -> bool {
        self.require_client_tls
    }

    pub fn metrics(&self) -> Arc<Metrics> {
        Arc::clone(&self.metrics)
    }

    /// Decide the plan for a described result set, or refuse it.
    ///
    /// Takes the principal's roles because the same column can resolve to
    /// different masks for different people — so a plan is only ever valid for
    /// the session that built it.
    pub(crate) fn plan_for(
        &self,
        snapshot: &Snapshot,
        fields: &[protocol::FieldDescription],
        roles: &HashSet<String>,
        analysis: &FieldAnalysis,
    ) -> Result<Plan, Rejection> {
        let mut plan = Vec::with_capacity(fields.len());
        for (index, field) in fields.iter().enumerate() {
            let provably_safe = analysis.safety.get(index).copied() == Some(Safety::Releasable);
            // Set only by the type-aware unclassified fallback when source
            // nullability permits it: a default mask that cannot be applied to
            // some value nulls that field instead of refusing the stream.
            // Operator-chosen masks stay fail-closed.
            let mut lenient = false;
            let mut type_aware_fallback = false;
            // A set operation can put values from several columns into one
            // output field, and CockroachDB reports the first branch's OID for
            // the whole thing. Believing it applies one column's mask to
            // another column's values, which is how a released `city` let a
            // masked `email` through in the clear. Treat the field as opaque.
            let spec = if !field.has_provenance() || !analysis.trust_provenance {
                // An expression we positively identified as carrying no column
                // value — `SELECT 1`, `now()`, `count(*)`. Passing it through is
                // the point of the analysis; see analysis/ for why the rule is
                // an allowlist of shapes rather than a search for column refs.
                if provably_safe {
                    self.metrics.record_rescued();
                    MaskSpec::new(Mask::None)
                } else if analysis.lineage.get(index) == Some(&Verdict::Release) {
                    // Every base column this derives from is explicitly
                    // released, so it cannot be carrying a masked value.
                    self.metrics.record_rescued();
                    MaskSpec::new(Mask::None)
                } else {
                    match analysis.summary_policy_for(index) {
                        // One shared summary-policy path, independent of
                        // whether optional lineage ran. Only an aggregate over
                        // exactly one syntax-verified bare column on qualified
                        // FROM ranges reaches either resolved state.
                        SummaryPolicy::Released => {
                            self.metrics.record_rescued();
                            MaskSpec::new(Mask::None)
                        }
                        SummaryPolicy::Masked(spec) => spec,
                        // Expressions and multi-argument regressions remain
                        // opaque because applying one source's mask after a
                        // transformation is not equivalent to masking it.
                        SummaryPolicy::NotApplicable | SummaryPolicy::Opaque => match self.opaque {
                            Opaque::Reject => {
                                // When lineage worked out *why*, say so.
                                // "derives from customer.c_first_name, which is
                                // masked" is the difference between a ticket
                                // and a rewrite.
                                if let Some(Verdict::Blocked(source)) = analysis.lineage.get(index)
                                {
                                    return Err(Rejection {
                                        cause: Cause::classify_opaque(&field.name, snapshot),
                                        message: format!(
                                            "pgmask: output column \"{}\" derives from {source}, \
                                             which is masked",
                                            field.name
                                        ),
                                        hint: Some(
                                            "An expression over a masked column cannot be masked \
                                             after the fact. Select a column that is released, or \
                                             aggregate in a way that cannot return a stored value."
                                                .into(),
                                        ),
                                    });
                                }
                                return Err(Rejection {
                                    cause: Cause::classify_opaque(&field.name, snapshot),
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
                                });
                            }
                            // Deliberately stricter than the type-aware
                            // unclassified fallback, and documented with it on
                            // `MaskSpec::for_unclassified`: a provenance-free
                            // field has no stable column identity to key a
                            // pseudonym domain, so NULL is the only honest
                            // default here.
                            Opaque::Mask => MaskSpec::new(Mask::Null),
                        },
                    }
                }
            } else {
                match snapshot.lookup(field.table_oid, field.column_id) {
                    Some(classification) => classification.for_roles(roles).clone(),
                    None => {
                        // A lookup miss is a staleness signal, and not only when
                        // the whole relation is unknown. A known relation with an
                        // unrecognised attnum means its columns changed under the
                        // snapshot — `ALTER TABLE ... DROP COLUMN x; ADD COLUMN x`
                        // moves x to a new attnum while keeping the table OID.
                        //
                        // Nudging only on unknown *relations* left that case to
                        // wait out the full refresh interval, and under `allow` a
                        // miss releases — so an explicitly-masked column that was
                        // reshaped was served in the clear for the whole window
                        // (measured: 30s of refresh interval, every query
                        // leaking). Nudge on any miss; the refresher keeps its own
                        // rate floor, so a storm of misses cannot become a query
                        // storm against the catalog.
                        self.catalog.note_unknown_relation();
                        match (self.unclassified, self.unclassified_mask) {
                            (Unclassified::Mask, UnclassifiedMask::TypeAware) => {
                                type_aware_fallback = true;
                                // Only a name the *catalog* resolved keys a
                                // pseudonym domain. There is no OID-based
                                // fallback: an OID is volatile across DDL and
                                // `field.name` is a client-chosen alias, so a
                                // handle keyed on either silently changes
                                // across a refresh or a rename — an unstable
                                // "stable handle" is worse than an honest NULL,
                                // which is what `for_unclassified` degrades to
                                // when no stable identity exists.
                                MaskSpec::for_unclassified(
                                    field.type_oid,
                                    field.format,
                                    field.type_mod,
                                    snapshot.name_of(field.table_oid, field.column_id),
                                )
                            }
                            (Unclassified::Mask, UnclassifiedMask::Null) => {
                                MaskSpec::new(Mask::Null)
                            }
                            (Unclassified::Allow, _) => MaskSpec::new(Mask::None),
                        }
                    }
                }
            };

            if type_aware_fallback {
                let source_is_not_null =
                    snapshot.is_not_null(field.table_oid, field.column_id) == Some(true);
                if source_is_not_null && spec.kind == Mask::Null {
                    let name = snapshot
                        .name_of(field.table_oid, field.column_id)
                        .unwrap_or(&field.name);
                    return Err(Rejection {
                        cause: Cause::NullabilityMismatch,
                        message: format!(
                            "pgmask: automatic mask for {name} would return NULL for a NOT NULL column"
                        ),
                        hint: Some(
                            "Classify the column with a compatible non-NULL mask, make the source column nullable, or explicitly choose unclassified_mask = \"null\"."
                                .into(),
                        ),
                    });
                }
                // For a declared NOT NULL source, a value-specific transform
                // failure must reject rather than surprise a strongly typed
                // client with NULL. Nullable and unresolved sources retain the
                // availability-oriented automatic fallback.
                lenient = !source_is_not_null;
            }

            // Catch type/format mismatches once here rather than per row, so a
            // misconfiguration refuses the result set instead of dying halfway
            // through a stream. A lenient (fallback-origin) spec is chosen
            // *from* `supports`, so it cannot fail this check.
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
                lenient,
            });
        }
        Ok(Arc::new(plan))
    }
}

/// Invert `[[role]]` declarations into principal -> roles.
pub(crate) fn roles_by_principal(
    roles: &[crate::catalog::Role],
) -> HashMap<String, HashSet<String>> {
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

/// Resolve every result field to one explicit reducing-aggregate policy state.
///
/// This is the seam between syntax analysis and catalog policy. It owns the
/// positional alignment and the safety gate, so callers cannot accidentally
/// treat a non-summary expression or a missing attribution as released.
pub(crate) fn resolve_summary_policies(
    inspection: Option<&analysis::StatementInspection<'_>>,
    field_count: usize,
    safety: &[Safety],
    snapshot: &Snapshot,
    roles: &HashSet<String>,
) -> Vec<SummaryPolicy> {
    let resolution = inspection.and_then(|value| value.summary_resolution(field_count));
    (0..field_count)
        .map(|index| {
            if safety.get(index) != Some(&Safety::Summary) {
                return SummaryPolicy::NotApplicable;
            }
            let Some(resolution) = resolution.as_ref() else {
                return SummaryPolicy::Opaque;
            };
            let Some(argument) = resolution.fields().get(index) else {
                return SummaryPolicy::Opaque;
            };
            resolve_summary_source(snapshot, resolution.relations(), argument, roles)
        })
        .collect()
}

/// Attribute a reducing aggregate's single bare column to exactly one FROM
/// relation and return that column's policy.
///
/// This is the catalog half of the summary-policy resolution in
/// [`Policy::plan_for`]: the statement half (`analysis::summary_resolution`)
/// hands back the FROM relations and the aggregate argument's column name, and
/// this function decides which relation owns the name and what that column is
/// masked with.
///
/// Returns [`SummaryPolicy::Opaque`] when an argument is not a bare column, a
/// relation is unqualified, ownership is not unique, or the catalog has never
/// heard of a relation or column. Explicit schema qualification is
/// load-bearing: the proxy does not track `search_path`, and a wrong relation
/// can carry a weaker mask than the relation PostgreSQL actually selected.
fn resolve_summary_source(
    snapshot: &Snapshot,
    relations: &[(String, String)],
    argument: &analysis::SummaryArgument,
    roles: &HashSet<String>,
) -> SummaryPolicy {
    let analysis::SummaryArgument::BareColumn(column) = argument else {
        return SummaryPolicy::Opaque;
    };
    let mut owners = 0usize;
    let mut owner: Option<&(String, String)> = None;
    for relation in relations {
        let Some(qualified) = qualify_relation(relation) else {
            return SummaryPolicy::Opaque;
        };
        // A relation the catalog has never heard of means ownership cannot be
        // ruled out, so nothing is attributed.
        let Some(columns) = snapshot.relation_columns(&qualified) else {
            return SummaryPolicy::Opaque;
        };
        if columns.iter().any(|c| c.as_str() == column) {
            owners = owners.saturating_add(1);
            owner = Some(relation);
        }
    }
    if owners != 1 {
        return SummaryPolicy::Opaque;
    }
    let Some(qualified) = owner.and_then(qualify_relation) else {
        return SummaryPolicy::Opaque;
    };
    let Some(classification) = snapshot.lookup_by_name(&qualified, column) else {
        return SummaryPolicy::Opaque;
    };
    let spec = classification.for_roles(roles).clone();
    if spec.is_passthrough() {
        SummaryPolicy::Released
    } else {
        SummaryPolicy::Masked(spec)
    }
}

/// `(schema, relname)` -> `schema.relname`. An absent schema is unresolved,
/// because PostgreSQL would consult session state this proxy does not track.
fn qualify_relation((schema, relname): &(String, String)) -> Option<String> {
    (!schema.is_empty()).then(|| format!("{schema}.{relname}"))
}

/// Policy constructors and field builders shared by this module's tests and
/// the session-level tests. They live here because `Policy`'s fields are
/// private to this module: tests build the exact policy they mean rather than
/// round-tripping through TOML.
#[cfg(test)]
pub(crate) mod test_support {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::protocol::FieldDescription;

    pub(crate) fn policy(unclassified: Unclassified, opaque: Opaque) -> Arc<Policy> {
        Arc::new(Policy {
            catalog: Arc::new(Catalog::default()),
            masker: Arc::new(Masker::new(b"k".to_vec())),
            unclassified,
            unclassified_mask: UnclassifiedMask::default(),
            opaque,
            metrics: Arc::new(Metrics::default()),
            summaries: Summaries::Allow,
            posture: Posture::Default,
            system_catalogs: SystemCatalogs::Refuse,
            lineage: Lineage::Refuse,
            roles: HashMap::new(),
            tls: None,
            require_client_tls: false,
            backend_tls: BackendTls::Disable,
            backend_ca: None,
            rate_limit: None,
            max_notices_per_exchange: None,
        })
    }

    /// The deployment configs the wire harnesses mirror run
    /// `lineage = "allow"`, which is what releases a pure expression column
    /// (`SELECT 1 AS x`). Under lineage refusal such a column is refused at
    /// the RowDescription, so tests that assert on released passthrough plans
    /// need the allow policy.
    pub(crate) fn policy_with_lineage_allow(
        unclassified: Unclassified,
        opaque: Opaque,
    ) -> Arc<Policy> {
        Arc::new(Policy {
            catalog: Arc::new(Catalog::default()),
            masker: Arc::new(Masker::new(b"k".to_vec())),
            unclassified,
            unclassified_mask: UnclassifiedMask::default(),
            opaque,
            metrics: Arc::new(Metrics::default()),
            summaries: Summaries::Allow,
            posture: Posture::Default,
            system_catalogs: SystemCatalogs::Refuse,
            lineage: Lineage::Allow,
            roles: HashMap::new(),
            tls: None,
            require_client_tls: false,
            backend_tls: BackendTls::Disable,
            backend_ca: None,
            rate_limit: None,
            max_notices_per_exchange: None,
        })
    }

    pub(crate) fn field(
        name: &str,
        table_oid: u32,
        column_id: i16,
        type_oid: u32,
    ) -> FieldDescription {
        field_with_format(name, table_oid, column_id, type_oid, 0)
    }

    pub(crate) fn field_with_format(
        name: &str,
        table_oid: u32,
        column_id: i16,
        type_oid: u32,
        format: i16,
    ) -> FieldDescription {
        FieldDescription {
            name: name.into(),
            table_oid,
            column_id,
            type_oid,
            type_mod: -1,
            format,
        }
    }

    pub(crate) fn policy_with_rate_limit(per_minute: u32, burst: u32) -> Arc<Policy> {
        Arc::new(Policy {
            catalog: Arc::new(Catalog::default()),
            masker: Arc::new(Masker::new(b"k".to_vec())),
            unclassified: Unclassified::Allow,
            unclassified_mask: UnclassifiedMask::default(),
            opaque: Opaque::Reject,
            metrics: Arc::new(Metrics::default()),
            summaries: Summaries::Allow,
            posture: Posture::Default,
            system_catalogs: SystemCatalogs::Refuse,
            lineage: Lineage::Refuse,
            roles: HashMap::new(),
            tls: None,
            require_client_tls: false,
            backend_tls: BackendTls::Disable,
            backend_ca: None,
            rate_limit: Some(PrincipalRateLimit::new(per_minute, burst).unwrap()),
            max_notices_per_exchange: None,
        })
    }

    pub(crate) fn policy_with_notice_cap(max: u32) -> Arc<Policy> {
        Arc::new(Policy {
            catalog: Arc::new(Catalog::default()),
            masker: Arc::new(Masker::new(b"k".to_vec())),
            unclassified: Unclassified::Allow,
            unclassified_mask: UnclassifiedMask::default(),
            opaque: Opaque::Reject,
            metrics: Arc::new(Metrics::default()),
            summaries: Summaries::Allow,
            posture: Posture::Default,
            system_catalogs: SystemCatalogs::Refuse,
            lineage: Lineage::Refuse,
            roles: HashMap::new(),
            tls: None,
            require_client_tls: false,
            backend_tls: BackendTls::Disable,
            backend_ca: None,
            rate_limit: None,
            max_notices_per_exchange: Some(max),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::test_support::*;
    use super::*;

    #[test]
    fn runtime_policy_construction_cannot_bypass_config_validation() {
        for text in [
            r#"
backend = "h:1"
catalog_dsn = "postgres://unused"
pseudonym_key = "short"
unclassified = "allow"
"#,
            r#"
backend = "h:1"
catalog_dsn = "postgres://unused"
pseudonym_key = "a-long-enough-key"
unclassified = "allow"

[[column]]
relation = "s.t"
column = "email"
mask = "redact"

[[column]]
relation = "S.T"
column = "EMAIL"
mask = "none"
"#,
        ] {
            let config: Config = toml::from_str(text).expect("fixture parses");
            assert!(
                Policy::from_config(&config, Arc::new(Catalog::default())).is_err(),
                "programmatic Config must cross the same validated policy seam"
            );
        }
    }

    #[test]
    fn opaque_field_is_rejected_by_default() {
        let p = policy(Unclassified::Allow, Opaque::Reject);
        let err = p
            .plan_for(
                &p.catalog.snapshot(),
                &[field("lower", 0, 0, 25)],
                &HashSet::new(),
                &FieldAnalysis {
                    safety: &[],
                    lineage: &[],
                    summary: &[],
                    trust_provenance: true,
                },
            )
            .expect_err("must reject");
        assert!(err.message.contains("no column provenance"));
    }

    #[test]
    fn opaque_field_can_be_masked_instead() {
        let p = policy(Unclassified::Allow, Opaque::Mask);
        let plan = p
            .plan_for(
                &p.catalog.snapshot(),
                &[field("lower", 0, 0, 25)],
                &HashSet::new(),
                &FieldAnalysis {
                    safety: &[],
                    lineage: &[],
                    summary: &[],
                    trust_provenance: true,
                },
            )
            .ok()
            .expect("must allow");
        assert_eq!(plan[0].spec.kind, Mask::Null);
    }

    #[test]
    fn unclassified_columns_are_masked_by_type() {
        let p = policy(Unclassified::Mask, Opaque::Reject);
        let mut snapshot = crate::catalog::Snapshot::default();
        let fields = [
            field("body", 16391, 1, 25),
            field("account_uuid", 16391, 2, crate::mask::OID_UUID),
            field("birthday", 16391, 3, crate::mask::OID_DATE),
            field("created_at", 16391, 4, crate::mask::OID_TIMESTAMP),
            field("last_seen_at", 16391, 5, crate::mask::OID_TIMESTAMPTZ),
            field("client_ip", 16391, 6, crate::mask::OID_INET),
            field("salary", 16391, 7, crate::mask::OID_INT8),
            field("sensitive_flag", 16391, 8, 16),
            field("payload", 16391, 9, 3802),
            field("values", 16391, 10, 1007),
            field("custom", 16391, 11, 16399),
            // inet/cidr binary is packed; type awareness must fall back to NULL
            // rather than selecting a mask that refuses the entire result set.
            field_with_format("packed_ip", 16391, 12, crate::mask::OID_CIDR, 1),
        ];
        for f in &fields {
            snapshot.insert_column_name_for_test(
                f.table_oid,
                f.column_id,
                &format!("demo.t.{}", f.name),
            );
        }
        let plan = p
            .plan_for(
                &snapshot,
                &fields,
                &HashSet::new(),
                &FieldAnalysis {
                    safety: &[],
                    lineage: &[],
                    summary: &[],
                    trust_provenance: true,
                },
            )
            .ok()
            .unwrap();
        assert_eq!(
            plan.iter().map(|field| field.spec.kind).collect::<Vec<_>>(),
            [
                Mask::Pseudonym,
                Mask::Pseudonym,
                Mask::DateYear,
                Mask::DateYear,
                Mask::DateYear,
                Mask::IpPrefix,
                Mask::Null,
                Mask::Null,
                Mask::Null,
                Mask::Null,
                Mask::Null,
                Mask::Null,
            ]
        );
        assert!(plan
            .iter()
            .all(|field| field.spec.supports(field.type_oid, field.format)));
        assert!(
            plan.iter().all(|field| field.lenient),
            "every fallback plan must degrade per-value rather than reject the stream"
        );
    }

    /// The wire protocol permits NULL for any result field, but a client that
    /// learned this stored column's NOT NULL contract will decode it into a
    /// non-optional type. An automatic fallback must fail before RowDescription
    /// rather than return a value that contradicts that contract.
    #[test]
    fn automatic_null_fallback_rejects_a_not_null_column() {
        let p = policy(Unclassified::Mask, Opaque::Reject);
        let mut snapshot = crate::catalog::Snapshot::default();
        snapshot.insert_column_name_for_test(16_391, 7, "demo.t.salary");
        snapshot.mark_not_null_for_test(16_391, 7);

        let err = p
            .plan_for(
                &snapshot,
                &[field("salary", 16_391, 7, crate::mask::OID_INT8)],
                &HashSet::new(),
                &FieldAnalysis {
                    safety: &[],
                    lineage: &[],
                    summary: &[],
                    trust_provenance: true,
                },
            )
            .expect_err("an automatic NULL must not violate source nullability");

        assert_eq!(err.cause, Cause::NullabilityMismatch);
        assert!(err.message.contains("NOT NULL"), "{}", err.message);
        assert!(err.message.contains("demo.t.salary"), "{}", err.message);
    }

    #[test]
    fn not_null_type_aware_mask_does_not_degrade_value_failures_to_null() {
        let p = policy(Unclassified::Mask, Opaque::Reject);
        let mut snapshot = crate::catalog::Snapshot::default();
        snapshot.insert_column_name_for_test(16_391, 3, "demo.t.birthday");
        snapshot.mark_not_null_for_test(16_391, 3);

        let plan = p
            .plan_for(
                &snapshot,
                &[field("birthday", 16_391, 3, crate::mask::OID_DATE)],
                &HashSet::new(),
                &FieldAnalysis {
                    safety: &[],
                    lineage: &[],
                    summary: &[],
                    trust_provenance: true,
                },
            )
            .ok()
            .expect("date-year can preserve NOT NULL for transformable values");

        assert_eq!(plan[0].spec.kind, Mask::DateYear);
        assert!(
            !plan[0].lenient,
            "a per-value failure must reject rather than produce NULL"
        );
    }

    /// A column the catalog has not resolved yet — a table created between
    /// refreshes — has no stable identity to key a pseudonym domain, so text
    /// and uuid fall back to honest NULL rather than to a handle that would
    /// silently change when the refresh lands or the client picks an alias.
    #[test]
    fn unclassified_columns_without_a_stable_name_null_rather_than_pseudonymise() {
        let p = policy(Unclassified::Mask, Opaque::Reject);
        let plan = p
            .plan_for(
                &p.catalog.snapshot(),
                &[
                    field("body", 16391, 1, 25),
                    field("account_uuid", 16391, 2, crate::mask::OID_UUID),
                    // No stable name is needed for masks that keep no linkable
                    // identity: coarse dates and IP prefixes stay type-aware.
                    field("birthday", 16391, 3, crate::mask::OID_DATE),
                ],
                &HashSet::new(),
                &FieldAnalysis {
                    safety: &[],
                    lineage: &[],
                    summary: &[],
                    trust_provenance: true,
                },
            )
            .ok()
            .unwrap();
        assert_eq!(
            plan.iter().map(|field| field.spec.kind).collect::<Vec<_>>(),
            [Mask::Null, Mask::Null, Mask::DateYear]
        );
    }

    /// `unclassified_mask = "null"` restores the strict pre-type-aware default.
    #[test]
    fn strict_null_unclassified_mask_nulls_every_type() {
        let mut p = policy(Unclassified::Mask, Opaque::Reject);
        Arc::get_mut(&mut p).unwrap().unclassified_mask = UnclassifiedMask::Null;
        let mut snapshot = crate::catalog::Snapshot::default();
        snapshot.insert_column_name_for_test(16391, 1, "demo.t.body");
        snapshot.mark_not_null_for_test(16391, 1);
        let plan = p
            .plan_for(
                &snapshot,
                &[
                    field("body", 16391, 1, 25),
                    field("birthday", 16391, 2, crate::mask::OID_DATE),
                ],
                &HashSet::new(),
                &FieldAnalysis {
                    safety: &[],
                    lineage: &[],
                    summary: &[],
                    trust_provenance: true,
                },
            )
            .ok()
            .unwrap();
        assert!(plan.iter().all(|field| field.spec.kind == Mask::Null));
    }

    /// A pseudonym is 16 characters (and up to 33 for email-shaped values), so
    /// a declared column width that cannot hold one falls back to NULL: a
    /// handle truncated by a fixed-width client binding collides with others.
    #[test]
    fn narrow_character_columns_null_rather_than_overflow_their_declared_width() {
        let p = policy(Unclassified::Mask, Opaque::Reject);
        let mut snapshot = crate::catalog::Snapshot::default();
        snapshot.insert_column_name_for_test(16391, 1, "demo.t.country");
        snapshot.insert_column_name_for_test(16391, 2, "demo.t.note");
        let mut narrow = field("country", 16391, 1, 1042);
        narrow.type_mod = 2 + 4; // char(2): declared limit plus VARHDRSZ
        let mut wide = field("note", 16391, 2, 1043);
        wide.type_mod = 120 + 4; // varchar(120)
        let plan = p
            .plan_for(
                &snapshot,
                &[narrow, wide],
                &HashSet::new(),
                &FieldAnalysis {
                    safety: &[],
                    lineage: &[],
                    summary: &[],
                    trust_provenance: true,
                },
            )
            .ok()
            .unwrap();
        assert_eq!(
            plan.iter().map(|field| field.spec.kind).collect::<Vec<_>>(),
            [Mask::Null, Mask::Pseudonym]
        );
    }

    #[test]
    fn unclassified_pseudonym_domains_are_stable_and_column_separated() {
        let p = policy(Unclassified::Mask, Opaque::Reject);
        let mut snapshot = crate::catalog::Snapshot::default();
        snapshot.insert_column_name_for_test(101, 1, "crm.activities.from_value");
        snapshot.insert_column_name_for_test(202, 7, "crm.activities.from_value");
        snapshot.insert_column_name_for_test(303, 1, "crm.activities.to_value");

        let plan = p
            .plan_for(
                &snapshot,
                &[
                    field("from_value", 101, 1, 25),
                    field("from_value", 202, 7, 25),
                    field("to_value", 303, 1, 25),
                ],
                &HashSet::new(),
                &FieldAnalysis {
                    safety: &[],
                    lineage: &[],
                    summary: &[],
                    trust_provenance: true,
                },
            )
            .ok()
            .unwrap();

        assert_eq!(plan[0].spec.domain, plan[1].spec.domain, "OID churn");
        assert_ne!(
            plan[0].spec.domain, plan[2].spec.domain,
            "unrelated columns must not become linkable"
        );
    }

    #[test]
    fn allow_mode_passes_unclassified_columns() {
        let p = policy(Unclassified::Allow, Opaque::Reject);
        let plan = p
            .plan_for(
                &p.catalog.snapshot(),
                &[field("email", 16391, 2, 25)],
                &HashSet::new(),
                &FieldAnalysis {
                    safety: &[],
                    lineage: &[],
                    summary: &[],
                    trust_provenance: true,
                },
            )
            .ok()
            .unwrap();
        assert_eq!(plan[0].spec.kind, Mask::None);
    }

    /// A reducing aggregate over a *released* column keeps passing through.
    #[test]
    fn a_summary_over_a_released_column_stays_exact() {
        let mut snapshot = crate::catalog::Snapshot::default();
        snapshot.insert_relation_for_test("demo.t", &[("salary", Mask::NumericBucket)]);
        snapshot.set_role_mask_for_test("demo.t", "salary", "nobody", Mask::Null);
        let p = policy_with_lineage_allow(Unclassified::Mask, Opaque::Reject);

        let plan = p
            .plan_for(
                &snapshot,
                &[field("sum", 0, 0, 20)],
                &HashSet::new(),
                &FieldAnalysis {
                    safety: &[Safety::Summary],
                    lineage: &[Verdict::Release],
                    summary: &[],
                    trust_provenance: true,
                },
            )
            .ok()
            .unwrap();
        // Lineage says the source is released, so the summary is the source's
        // exact sum — `sum(id)` over an unmasked `id` keeps its precision.
        assert_eq!(plan[0].spec.kind, Mask::None);
    }

    /// A reducing aggregate over a *masked* column is masked with that column's
    /// own mask instead of being refused. That is what closes `sum(x) WHERE
    /// unique = 1`: whether the predicate collapses the set to one row is a
    /// property of the data, so the precision is given up rather than the
    /// summary — a sum over a bucketed column is a bucket, whatever the filter.
    #[test]
    fn a_summary_over_a_masked_column_is_masked_with_its_source_mask() {
        let mut snapshot = crate::catalog::Snapshot::default();
        snapshot.insert_relation_for_test("demo.t", &[("salary", Mask::NumericBucket)]);
        let p = policy_with_lineage_allow(Unclassified::Mask, Opaque::Reject);

        let plan = p
            .plan_for(
                &snapshot,
                // Aggregate outputs carry no table provenance, so the field is
                // an unprovenanced `sum` of type int8.
                &[field("sum", 0, 0, 20)],
                &HashSet::new(),
                &FieldAnalysis {
                    safety: &[Safety::Summary],
                    lineage: &[Verdict::Blocked("demo.t.salary".into())],
                    summary: &[SummaryPolicy::Masked(MaskSpec::new(Mask::NumericBucket))],
                    trust_provenance: true,
                },
            )
            .ok()
            .unwrap();
        assert_eq!(
            plan[0].spec.kind,
            Mask::NumericBucket,
            "the aggregate output must take its source column's mask"
        );

        // The mask posture makes no difference to a summary: it is maskable,
        // so it is never simply nulled.
        let p2 = policy_with_lineage_allow(Unclassified::Mask, Opaque::Mask);
        let plan2 = p2
            .plan_for(
                &snapshot,
                &[field("sum", 0, 0, 20)],
                &HashSet::new(),
                &FieldAnalysis {
                    safety: &[Safety::Summary],
                    lineage: &[Verdict::Blocked("demo.t.salary".into())],
                    summary: &[SummaryPolicy::Masked(MaskSpec::new(Mask::NumericBucket))],
                    trust_provenance: true,
                },
            )
            .ok()
            .unwrap();
        assert_eq!(plan2[0].spec.kind, Mask::NumericBucket);

        // An unresolvable summary falls back to the opaque posture instead of
        // passing through.
        let err = p
            .plan_for(
                &snapshot,
                &[field("sum", 0, 0, 20)],
                &HashSet::new(),
                &FieldAnalysis {
                    safety: &[Safety::Summary],
                    lineage: &[Verdict::Unresolved],
                    summary: &[],
                    trust_provenance: true,
                },
            )
            .expect_err("an unbounded summary must not pass through");
        assert!(
            err.message.contains("no column provenance"),
            "got: {}",
            err.message
        );
    }

    /// Lineage reports only one blocked source even when an expression derives
    /// from several columns or transforms one before aggregating it. That is
    /// enough for a diagnostic, not enough to choose an output mask. Only the
    /// syntax-checked single-bare-column resolution may make that choice.
    #[test]
    fn a_lineage_block_alone_cannot_choose_a_summary_mask() {
        let mut snapshot = crate::catalog::Snapshot::default();
        snapshot.insert_relation_for_test("demo.t", &[("a", Mask::NumericBucket)]);
        let p = policy_with_lineage_allow(Unclassified::Mask, Opaque::Reject);

        let err = p
            .plan_for(
                &snapshot,
                &[field("sum", 0, 0, 20)],
                &HashSet::new(),
                &FieldAnalysis {
                    safety: &[Safety::Summary],
                    lineage: &[Verdict::Blocked("demo.t.a".into())],
                    summary: &[],
                    trust_provenance: true,
                },
            )
            .expect_err("lineage alone cannot prove a mask is valid after aggregation");
        assert!(err.message.contains("derives from demo.t.a"));
    }

    #[test]
    fn an_unqualified_summary_relation_cannot_choose_a_catalog_policy() {
        let mut snapshot = crate::catalog::Snapshot::default();
        snapshot.insert_relation_for_test("public.payroll", &[("salary", Mask::NumericBucket)]);

        assert_eq!(
            resolve_summary_source(
                &snapshot,
                &[(String::new(), "payroll".into())],
                &analysis::SummaryArgument::BareColumn("salary".into()),
                &HashSet::new(),
            ),
            SummaryPolicy::Opaque,
            "the backend may resolve payroll through search_path to another schema"
        );
    }

    #[test]
    fn text_mask_on_a_non_text_column_is_refused_at_plan_time() {
        let mut snapshot = crate::catalog::Snapshot::default();
        snapshot.insert_for_test(16391, 1, Mask::Pseudonym, "demo.t.id");
        let p = Arc::new(Policy {
            require_client_tls: false,
            catalog: Arc::new(Catalog::from_snapshot_for_test(snapshot)),
            masker: Arc::new(Masker::new(b"k".to_vec())),
            unclassified: Unclassified::Allow,
            unclassified_mask: UnclassifiedMask::default(),
            opaque: Opaque::Reject,
            metrics: Arc::new(Metrics::default()),
            summaries: Summaries::Allow,
            posture: Posture::Default,
            system_catalogs: SystemCatalogs::Refuse,
            lineage: Lineage::Refuse,
            roles: HashMap::new(),
            tls: None,
            backend_tls: BackendTls::Disable,
            backend_ca: None,
            rate_limit: None,
            max_notices_per_exchange: None,
        });
        // int4, not a text type: pseudonym rewrites values as text.
        let err = p
            .plan_for(
                &p.catalog.snapshot(),
                &[field("id", 16391, 1, 23)],
                &HashSet::new(),
                &FieldAnalysis {
                    safety: &[],
                    lineage: &[],
                    summary: &[],
                    trust_provenance: true,
                },
            )
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

    /// The `lineage = "refuse"` default still masks a reducing aggregate when
    /// the backstop attributes its bare column to a masked catalog column —
    /// the 0.1.92 contract under the config that ships on by default.
    #[test]
    fn a_summary_over_a_masked_column_is_masked_without_lineage() {
        let p = policy(Unclassified::Mask, Opaque::Reject);
        let snapshot = p.catalog.snapshot();
        let plan = p
            .plan_for(
                &snapshot,
                &[field("sum", 0, 0, 20)],
                &HashSet::new(),
                &FieldAnalysis {
                    safety: &[Safety::Summary],
                    lineage: &[],
                    summary: &[SummaryPolicy::Masked(MaskSpec::new(Mask::NumericBucket))],
                    trust_provenance: true,
                },
            )
            .ok()
            .expect("the fallback must mask, not refuse");
        assert_eq!(
            plan[0].spec.kind,
            Mask::NumericBucket,
            "same as the lineage-resolved summary"
        );
    }

    /// Without an attribution the summary keeps the opaque posture. A released
    /// attribution is safe to preserve because it was resolved only from an
    /// explicitly schema-qualified range.
    #[test]
    fn an_unattributed_summary_stays_opaque_without_lineage() {
        let p = policy(Unclassified::Mask, Opaque::Reject);
        let err = p
            .plan_for(
                &p.catalog.snapshot(),
                &[field("sum", 0, 0, 20)],
                &HashSet::new(),
                &FieldAnalysis {
                    safety: &[Safety::Summary],
                    lineage: &[],
                    summary: &[SummaryPolicy::Opaque],
                    trust_provenance: true,
                },
            )
            .expect_err("without an attribution the opaque posture governs");
        assert!(
            err.message.contains("no column provenance"),
            "got: {}",
            err.message
        );

        let p2 = policy(Unclassified::Mask, Opaque::Mask);
        let plan = p2
            .plan_for(
                &p2.catalog.snapshot(),
                &[field("sum", 0, 0, 20)],
                &HashSet::new(),
                &FieldAnalysis {
                    safety: &[Safety::Summary],
                    lineage: &[],
                    summary: &[SummaryPolicy::Released],
                    trust_provenance: true,
                },
            )
            .ok()
            .expect("mask posture must not reject");
        assert_eq!(plan[0].spec.kind, Mask::None);
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
}
