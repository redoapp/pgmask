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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use arc_swap::ArcSwap;
use sha2::{Digest, Sha256};

use crate::analysis::{self, Safety};
use crate::catalog::{
    Catalog, ColumnRule, Config, Lineage, Opaque, Posture, SemanticType, Snapshot, Summaries,
    SystemCatalogs, Unclassified, UnclassifiedMask,
};
use crate::lineage::Verdict;
use crate::mask::{JsonProjection, Mask, MaskSpec, Masker};
use crate::metrics::{Cause, Metrics};
use crate::plan_state::{FieldPlan, Plan};
use crate::protocol;
use crate::rate_limit::PrincipalRateLimit;
use crate::tls::BackendTls;
use secrecy::ExposeSecret;
use tokio_rustls::TlsAcceptor;

mod json_extract;
use json_extract::resolve_json_extract_policies;

/// Bind-time settings a reload cannot honour. Changing them needs a restart.
#[derive(Debug, Clone)]
struct ProcessIdentity {
    listen: String,
    backend: String,
    catalog_dsn: String,
    metrics_listen: Option<String>,
}

impl ProcessIdentity {
    fn from_config(config: &Config) -> Self {
        Self {
            listen: config.listen.clone(),
            backend: config.backend.clone(),
            catalog_dsn: config.catalog_dsn.clone(),
            metrics_listen: config.metrics_listen.clone(),
        }
    }

    fn mismatches(&self, config: &Config) -> Vec<&'static str> {
        let mut names = Vec::new();
        if config.listen != self.listen {
            names.push("listen");
        }
        if config.backend != self.backend {
            names.push("backend");
        }
        if config.catalog_dsn != self.catalog_dsn {
            names.push("catalog_dsn");
        }
        if config.metrics_listen != self.metrics_listen {
            names.push("metrics_listen");
        }
        names
    }
}

/// What a successful [`Policy::reload_from_path`] / [`Policy::apply_config`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReloadReport {
    /// The file bytes matched the last successful reload; only TLS PEMs were
    /// re-read.
    pub unchanged: bool,
    /// Names were re-resolved against `pg_class`.
    pub catalog_re_resolved: bool,
    /// Keys that still require a process restart.
    pub restart_required: Vec<&'static str>,
}

/// Reloadable knobs every session observes on the next decision, not at accept.
#[derive(Clone)]
pub(crate) struct LivePolicy {
    pub(crate) unclassified: Unclassified,
    pub(crate) unclassified_mask: UnclassifiedMask,
    pub(crate) opaque: Opaque,
    pub(crate) summaries: Summaries,
    pub(crate) posture: Posture,
    pub(crate) system_catalogs: SystemCatalogs,
    pub(crate) lineage: Lineage,
    roles: HashMap<String, HashSet<String>>,
    require_client_tls: bool,
    backend_tls: BackendTls,
    backend_ca: Option<String>,
    rate_limit: Option<PrincipalRateLimit>,
    max_notices_per_exchange: Option<u32>,
    tls_cert: Option<String>,
    tls_key: Option<String>,
}

pub struct Policy {
    pub(crate) catalog: Arc<Catalog>,
    masker: ArcSwap<Masker>,
    live: ArcSwap<LivePolicy>,
    tls: ArcSwap<Option<TlsAcceptor>>,
    pub(crate) metrics: Arc<Metrics>,
    identity: ProcessIdentity,
    /// Bumped on a file reload that changes classification or live knobs, so
    /// cached statement/portal plans are dropped the same way a catalog
    /// refresh drops them. Independent of [`Catalog::generation`]: a role
    /// change does not re-resolve OIDs but still invalidates plans.
    epoch: AtomicU64,
    pub reloads: AtomicU64,
    pub failed_reloads: AtomicU64,
    last_file_sha: ArcSwap<Option<[u8; 32]>>,
    reload: tokio::sync::Mutex<()>,
}

/// Brackets a policy swap with two distinct generations.
///
/// The first invalidates decisions made before the swap starts. The `Drop`
/// bump invalidates a decision rebuilt while catalog resolution was in flight.
/// Making the second bump structural avoids an early return or future `?`
/// silently reopening that race.
pub(crate) struct PolicyChange<'a> {
    epoch: &'a AtomicU64,
}

impl<'a> PolicyChange<'a> {
    fn begin(epoch: &'a AtomicU64) -> Self {
        epoch.fetch_add(1, Ordering::Relaxed);
        Self { epoch }
    }
}

impl Drop for PolicyChange<'_> {
    fn drop(&mut self) {
        self.epoch.fetch_add(1, Ordering::Relaxed);
    }
}

/// Why a result set was refused: the words the client sees, plus the bucket the
/// counters see.
pub(crate) struct Rejection {
    pub(crate) message: String,
    pub(crate) hint: Option<String>,
    pub(crate) cause: Cause,
}

/// Everything `Policy::plan_for` needs to classify one result set, grouped so
/// the decision hub stays under the clippy argument budget.
pub(crate) struct FieldAnalysis<'a> {
    /// Per-field analysis verdict (`Summary`, `Releasable`, `Unknown`, …).
    pub safety: &'a [Safety],
    /// Per-field lineage verdict, when lineage ran (`Release`/`Blocked`/…).
    pub lineage: &'a [Verdict],
    /// Per-field policy for a syntax-verified expression projection.
    pub expression: &'a [ExpressionPolicy],
    /// Whether the engine's column provenance is believed (set-op distrust).
    pub trust_provenance: bool,
}

/// The complete policy state for one syntax-verified expression field.
///
/// Keeping `Released` distinct from `Masked` prevents a missing attribution
/// (`Opaque`) from being represented as a permissive `None` mask. Keeping
/// `NotApplicable` distinct from `Opaque` makes the safety gate explicit too.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ExpressionPolicy {
    NotApplicable,
    Opaque,
    Released,
    Masked {
        spec: MaskSpec,
        projection: Option<JsonProjection>,
    },
}

impl FieldAnalysis<'_> {
    /// The resolved policy for one syntax-verified expression field.
    ///
    /// Gated on the field actually being `Safety::Summary` or
    /// `Safety::JsonExtract`, not merely containing an aggregate or JSON
    /// operator. The source can be masked or explicitly released; schema
    /// qualification removes the `search_path` guess that made passthrough
    /// unsafe in earlier fallbacks.
    pub(crate) fn expression_policy_for(&self, index: usize) -> ExpressionPolicy {
        if !matches!(
            self.safety.get(index),
            Some(Safety::Summary | Safety::JsonExtract)
        ) {
            return ExpressionPolicy::NotApplicable;
        }
        self.expression
            .get(index)
            .cloned()
            .unwrap_or(ExpressionPolicy::Opaque)
    }
}

impl Policy {
    pub fn from_config(config: &Config, catalog: Arc<Catalog>) -> Result<Self> {
        // `Config` is public because the classifier and test adapters build it
        // programmatically. File loading validates it, but runtime policy must
        // not depend on which construction path the caller used.
        config.validate()?;
        catalog.set_refresh_schedule(
            Duration::from_secs(config.catalog_refresh_seconds),
            Duration::from_secs(config.catalog_refresh_min_seconds),
        );
        let live = live_from_config(config, None)?;
        let tls = tls_from_config(config)?;
        Ok(Self {
            catalog,
            masker: ArcSwap::from_pointee(Masker::new(
                config.pseudonym_key.expose_secret().as_bytes().to_vec(),
            )),
            live: ArcSwap::from_pointee(live),
            tls: ArcSwap::from_pointee(tls),
            metrics: Arc::new(Metrics::default()),
            identity: ProcessIdentity::from_config(config),
            epoch: AtomicU64::new(0),
            reloads: AtomicU64::new(0),
            failed_reloads: AtomicU64::new(0),
            last_file_sha: ArcSwap::from_pointee(None),
            reload: tokio::sync::Mutex::new(()),
        })
    }

    /// Record the bytes of the file that produced the current policy, so a
    /// SIGHUP with no edits skips the catalog round-trip.
    pub fn remember_file_bytes(&self, bytes: &[u8]) {
        self.last_file_sha
            .store(Arc::new(Some(sha256_bytes(bytes))));
    }

    /// Re-read `path`, parse it, and swap live policy if it is valid.
    ///
    /// A parse, validation, TLS, or catalog-resolve failure keeps the previous
    /// policy in full. In-flight result sets keep the plan they were described
    /// with; the next Describe or simple Query observes the new generation.
    pub async fn reload_from_path(&self, path: &str) -> Result<ReloadReport> {
        let _serialise = self.reload.lock().await;
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(err) => {
                self.note_reload_failure();
                anyhow::bail!("reading {path}: {err}");
            }
        };
        let sha = sha256_bytes(text.as_bytes());
        if **self.last_file_sha.load() == Some(sha) {
            if let Err(err) = self.refresh_tls_from_live_paths() {
                self.note_reload_failure();
                return Err(err);
            }
            self.note_reload_success();
            // Say so. An operator edits a file and sends SIGHUP; if the bytes
            // did not change, the reload is a no-op and the only other
            // evidence is a counter nobody watches to confirm a manual
            // action. Silence here reads exactly like "the signal went
            // nowhere", so editing the wrong path — a copy, a stale symlink,
            // the wrong container mount — looked identical to success. This
            // is also the certificate-rotation path, where "did it take?" is
            // the whole question.
            tracing::info!(
                "config reload: {path} is byte-identical, so policy is unchanged; \
                 tls_cert/tls_key were re-read"
            );
            return Ok(ReloadReport {
                unchanged: true,
                ..ReloadReport::default()
            });
        }
        let config: Config = match toml::from_str(&text) {
            Ok(config) => config,
            Err(err) => {
                self.note_reload_failure();
                anyhow::bail!("parsing {path}: {err}");
            }
        };
        match self.apply_config_locked(&config).await {
            Ok(mut report) => {
                self.last_file_sha.store(Arc::new(Some(sha)));
                self.note_reload_success();
                if !report.restart_required.is_empty() {
                    tracing::warn!(
                        ignored = ?report.restart_required,
                        "config reload applied policy; listen/backend/catalog_dsn/metrics_listen still need a restart"
                    );
                } else {
                    tracing::info!(
                        catalog_re_resolved = report.catalog_re_resolved,
                        "config reloaded from {path}"
                    );
                }
                report.unchanged = false;
                Ok(report)
            }
            Err(err) => {
                self.note_reload_failure();
                Err(err)
            }
        }
    }

    /// Apply an already-parsed config. Used by tests and by [`Self::reload_from_path`].
    pub async fn apply_config(&self, config: &Config) -> Result<ReloadReport> {
        let _serialise = self.reload.lock().await;
        match self.apply_config_locked(config).await {
            Ok(report) => {
                self.note_reload_success();
                Ok(report)
            }
            Err(err) => {
                self.note_reload_failure();
                Err(err)
            }
        }
    }

    async fn apply_config_locked(&self, config: &Config) -> Result<ReloadReport> {
        config.validate()?;
        let restart_required = self.identity.mismatches(config);
        let tls = tls_from_config(config)?;
        let previous = self.live.load_full();
        let live = live_from_config(config, previous.rate_limit.as_ref())?;
        let rules: Vec<ColumnRule> = config.column_rules().cloned().collect();
        let catalog_re_resolved = !self.catalog.spec_matches(&rules, &config.semantic_type);
        let key_changed =
            self.masker.load().key_bytes() != config.pseudonym_key.expose_secret().as_bytes();
        let live_changed = live_differs(&previous, &live);
        warn_if_transport_relaxed(&previous, &live, tls.is_some());

        // Two bumps when anything observable changes:
        //
        // 1. Before the swap, so a cached plan cannot outlive the old file
        //    once a loosened rule is about to become visible. `replace_spec`
        //    talks to Postgres; that window is long.
        // 2. After the swap, so a plan rebuilt in that window — old live
        //    knobs, already stamped with bump (1)'s generation — cannot be
        //    reused against the new snapshot. One bump only, on either side,
        //    leaves a reusable cache: before-only stamps old decisions as
        //    fresh; after-only leaves old caches matching until the bump,
        //    while the new live is already loaded.
        //
        // If catalog resolution then fails, both bumps still run: sessions
        // rebuild against the previous snapshot twice — over-invalidation,
        // not a release.
        let bump = catalog_re_resolved || live_changed || key_changed;
        let _change = bump.then(|| PolicyChange::begin(&self.epoch));
        if catalog_re_resolved {
            let types: HashMap<String, SemanticType> = config
                .semantic_type
                .iter()
                .map(|semantic| (semantic.name.clone(), semantic.clone()))
                .collect();
            self.catalog.replace_spec(rules, types).await?;
        }
        self.catalog.set_refresh_schedule(
            Duration::from_secs(config.catalog_refresh_seconds),
            Duration::from_secs(config.catalog_refresh_min_seconds),
        );
        if key_changed {
            self.masker.store(Arc::new(Masker::new(
                config.pseudonym_key.expose_secret().as_bytes().to_vec(),
            )));
        }
        self.live.store(Arc::new(live));
        self.tls.store(Arc::new(tls));
        Ok(ReloadReport {
            unchanged: false,
            catalog_re_resolved,
            restart_required,
        })
    }

    fn note_reload_success(&self) {
        self.reloads.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("pgmask_config_reloads_total").increment(1);
    }

    fn note_reload_failure(&self) {
        self.failed_reloads.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("pgmask_config_reload_failures_total").increment(1);
    }

    fn refresh_tls_from_live_paths(&self) -> Result<()> {
        let live = self.live.load();
        let config_tls = match (&live.tls_cert, &live.tls_key) {
            (Some(cert), Some(key)) => Some(crate::tls::load_acceptor(cert, key)?),
            (None, None) => None,
            _ => anyhow::bail!("tls_cert and tls_key must be set together"),
        };
        self.tls.store(Arc::new(config_tls));
        Ok(())
    }

    /// Catalog generation plus policy-file epoch. Cached plans are valid only
    /// for one value of this.
    pub fn generation(&self) -> u64 {
        self.catalog
            .generation()
            .wrapping_add(self.epoch.load(Ordering::Relaxed))
    }

    /// Roles held by a verified principal.
    pub fn roles_of(&self, principal: &str) -> HashSet<String> {
        self.live
            .load()
            .roles
            .get(principal)
            .cloned()
            .unwrap_or_default()
    }

    pub fn role_count(&self) -> usize {
        self.live.load().roles.len()
    }

    pub(crate) fn live(&self) -> Arc<LivePolicy> {
        self.live.load_full()
    }

    pub(crate) fn posture(&self) -> Posture {
        self.live.load().posture
    }

    pub(crate) fn rate_limit(&self) -> Option<PrincipalRateLimit> {
        self.live.load().rate_limit.clone()
    }

    pub(crate) fn max_notices_per_exchange(&self) -> Option<u32> {
        self.live.load().max_notices_per_exchange
    }

    pub(crate) fn masker(&self) -> Arc<Masker> {
        self.masker.load_full()
    }

    pub(crate) fn tls_acceptor(&self) -> Option<TlsAcceptor> {
        (*self.tls.load_full()).clone()
    }

    pub(crate) fn backend_tls(&self) -> BackendTls {
        self.live.load().backend_tls
    }

    pub(crate) fn backend_ca(&self) -> Option<String> {
        self.live.load().backend_ca.clone()
    }

    #[cfg(test)]
    pub(crate) fn unclassified(&self) -> Unclassified {
        self.live.load().unclassified
    }

    #[cfg(test)]
    pub(crate) fn set_unclassified_mask_for_test(&self, mask: UnclassifiedMask) {
        let mut live = (**self.live.load()).clone();
        live.unclassified_mask = mask;
        self.live.store(Arc::new(live));
    }

    #[cfg(test)]
    pub(crate) fn set_unclassified_for_test(&self, unclassified: Unclassified) {
        let mut live = (**self.live.load()).clone();
        live.unclassified = unclassified;
        self.live.store(Arc::new(live));
    }

    #[cfg(test)]
    pub(crate) fn begin_change_for_test(&self) -> PolicyChange<'_> {
        PolicyChange::begin(&self.epoch)
    }

    #[cfg(test)]
    pub(crate) fn set_roles_for_test(&self, roles: HashMap<String, HashSet<String>>) {
        let mut live = (**self.live.load()).clone();
        live.roles = roles;
        self.live.store(Arc::new(live));
    }

    /// Whether a certificate is *configured*. Deliberately not named
    /// `has_client_tls`: that reads as a property of the connection, and a
    /// configured certificate says nothing about whether any given client
    /// used it. `Session::client_tls` is the per-connection fact.
    pub fn client_tls_configured(&self) -> bool {
        self.tls.load().is_some()
    }

    pub fn client_tls_required(&self) -> bool {
        self.live.load().require_client_tls
    }

    pub fn metrics(&self) -> Arc<Metrics> {
        Arc::clone(&self.metrics)
    }

    /// Decide the plan for a described result set, or refuse it.
    ///
    /// The session loads one [`LivePolicy`] for the whole `RowDescription` and
    /// passes it in so hostile/summary/opaque/unclassified cannot tear across
    /// a reload mid-plan. A plan is only valid for the roles it was built with.
    pub(crate) fn plan_for_with(
        &self,
        live: &LivePolicy,
        snapshot: &Snapshot,
        fields: &[protocol::FieldDescription],
        roles: &HashSet<String>,
        analysis: &FieldAnalysis,
    ) -> Result<Plan, Rejection> {
        let masker = self.masker.load();
        let mut plan = Vec::with_capacity(fields.len());
        for (index, field) in fields.iter().enumerate() {
            let provably_safe = analysis.safety.get(index).copied() == Some(Safety::Releasable);
            // Set only by the type-aware unclassified fallback when source
            // nullability permits it: a default mask that cannot be applied to
            // some value nulls that field instead of refusing the stream.
            // Operator-chosen masks stay fail-closed.
            let mut lenient = false;
            let mut type_aware_fallback = false;
            let mut json_projection = None;
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
                    match analysis.expression_policy_for(index) {
                        ExpressionPolicy::Released => {
                            self.metrics.record_rescued();
                            MaskSpec::new(Mask::None)
                        }
                        ExpressionPolicy::Masked { spec, projection } => {
                            json_projection = projection;
                            spec
                        }
                        ExpressionPolicy::NotApplicable | ExpressionPolicy::Opaque => self
                            .plan_opaque_field(
                                snapshot,
                                field,
                                analysis.lineage.get(index),
                                live.opaque,
                            )?,
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
                        match (live.unclassified, live.unclassified_mask) {
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

            // Absorb the pseudonym domain into the HMAC state once per plan
            // rather than once per value; `None` for non-digest masks.
            let primed = masker.prime(&spec);
            plan.push(FieldPlan {
                spec,
                json_projection,
                type_oid: field.type_oid,
                format: field.format,
                lenient,
                primed,
            });
        }
        Ok(Arc::new(plan))
    }

    #[cfg(test)]
    pub(crate) fn plan_for(
        &self,
        snapshot: &Snapshot,
        fields: &[protocol::FieldDescription],
        roles: &HashSet<String>,
        analysis: &FieldAnalysis,
    ) -> Result<Plan, Rejection> {
        self.plan_for_with(&self.live.load(), snapshot, fields, roles, analysis)
    }

    fn plan_opaque_field(
        &self,
        snapshot: &Snapshot,
        field: &protocol::FieldDescription,
        lineage: Option<&Verdict>,
        opaque: Opaque,
    ) -> Result<MaskSpec, Rejection> {
        if opaque == Opaque::Mask {
            return Ok(MaskSpec::new(Mask::Null));
        }
        if let Some(Verdict::Blocked(source)) = lineage {
            return Err(Rejection {
                cause: Cause::classify_opaque(&field.name, snapshot),
                message: format!(
                    "pgmask: output column \"{}\" derives from {source}, which is masked",
                    field.name
                ),
                hint: Some(
                    "An expression over a masked column cannot be masked after the fact. \
                     Select a released column, a supported summary, or a literal JSON extract \
                     whose pointer policy can be applied to the result."
                        .into(),
                ),
            });
        }
        Err(Rejection {
            cause: Cause::classify_opaque(&field.name, snapshot),
            message: format!(
                "pgmask: output column \"{}\" has no column provenance, so it cannot be classified",
                field.name
            ),
            hint: Some(
                "Select the underlying column directly. Expressions, set operations \
                 (UNION/INTERSECT/EXCEPT), recursive CTEs and SETOF-returning functions erase \
                 provenance. Rescued expressions need one syntax-verified, catalog-attributed \
                 source."
                    .into(),
            ),
        })
    }
}

fn warn_if_transport_relaxed(previous: &LivePolicy, next: &LivePolicy, tls_configured: bool) {
    if previous.require_client_tls && !next.require_client_tls {
        tracing::warn!(
            "config reload set require_client_tls = false — new clients may connect \
             in plaintext; existing sessions are unchanged"
        );
    }
    if previous.tls_cert.is_some() && !tls_configured {
        tracing::warn!(
            "config reload removed tls_cert/tls_key — new clients will not negotiate TLS"
        );
    }
    if previous.backend_tls != BackendTls::Disable && next.backend_tls == BackendTls::Disable {
        tracing::warn!(
            "config reload set backend_tls = disable — new sessions send unmasked rows \
             to Postgres in the clear"
        );
    }
}

fn tls_from_config(config: &Config) -> Result<Option<TlsAcceptor>> {
    match (&config.tls_cert, &config.tls_key) {
        (Some(cert), Some(key)) => Ok(Some(crate::tls::load_acceptor(cert, key)?)),
        (None, None) => Ok(None),
        _ => anyhow::bail!("tls_cert and tls_key must be set together"),
    }
}

fn live_from_config(
    config: &Config,
    previous_rate: Option<&PrincipalRateLimit>,
) -> Result<LivePolicy> {
    let rate_limit = if config.rate_limit_per_minute == 0 {
        None
    } else {
        let burst = config.effective_rate_limit_burst();
        match previous_rate {
            Some(prev)
                if prev.per_minute() == config.rate_limit_per_minute && prev.burst() == burst =>
            {
                Some(prev.clone())
            }
            _ => Some(PrincipalRateLimit::new(
                config.rate_limit_per_minute,
                burst,
            )?),
        }
    };
    let max_notices_per_exchange = match config.max_notices_per_exchange {
        0 => None,
        n => Some(n),
    };
    Ok(LivePolicy {
        unclassified: config.unclassified,
        unclassified_mask: config.unclassified_mask,
        opaque: config.opaque,
        summaries: config.effective_summaries(),
        posture: config.posture,
        system_catalogs: config.system_catalogs,
        lineage: config.lineage,
        roles: roles_by_principal(&config.role),
        require_client_tls: config.client_tls_required(),
        backend_tls: config.backend_tls,
        backend_ca: config.backend_ca.clone(),
        rate_limit,
        max_notices_per_exchange,
        tls_cert: config.tls_cert.clone(),
        tls_key: config.tls_key.clone(),
    })
}

fn live_differs(a: &LivePolicy, b: &LivePolicy) -> bool {
    a.unclassified != b.unclassified
        || a.unclassified_mask != b.unclassified_mask
        || a.opaque != b.opaque
        || a.summaries != b.summaries
        || a.posture != b.posture
        || a.system_catalogs != b.system_catalogs
        || a.lineage != b.lineage
        || a.roles != b.roles
        || a.require_client_tls != b.require_client_tls
        || a.backend_tls != b.backend_tls
        || a.backend_ca != b.backend_ca
        || a.max_notices_per_exchange != b.max_notices_per_exchange
        || a.tls_cert != b.tls_cert
        || a.tls_key != b.tls_key
        || match (&a.rate_limit, &b.rate_limit) {
            (None, None) => false,
            (Some(a), Some(b)) => a.per_minute() != b.per_minute() || a.burst() != b.burst(),
            _ => true,
        }
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
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

/// Resolve every syntax-verified expression through one policy seam.
///
/// `plan_for` does not know whether a rescued expression was a reducing
/// aggregate or a JSON projection. Analysis chooses the shape; this function
/// aligns that shape's catalog result to the corresponding output field.
pub(crate) fn resolve_expression_policies(
    inspection: Option<&analysis::StatementInspection<'_>>,
    field_count: usize,
    safety: &[Safety],
    snapshot: &Snapshot,
    roles: &HashSet<String>,
) -> Vec<ExpressionPolicy> {
    let summaries = resolve_summary_policies(inspection, field_count, safety, snapshot, roles);
    let json_extracts =
        resolve_json_extract_policies(inspection, field_count, safety, snapshot, roles);

    (0..field_count)
        .map(|index| match safety.get(index) {
            Some(Safety::Summary) => summaries
                .get(index)
                .cloned()
                .unwrap_or(ExpressionPolicy::Opaque),
            Some(Safety::JsonExtract) => json_extracts
                .get(index)
                .cloned()
                .unwrap_or(ExpressionPolicy::Opaque),
            _ => ExpressionPolicy::NotApplicable,
        })
        .collect()
}

/// Resolve every result field to one explicit reducing-aggregate policy state.
///
/// This is the seam between syntax analysis and catalog policy. It owns the
/// positional alignment and the safety gate, so callers cannot accidentally
/// treat a non-summary expression or a missing attribution as released.
fn resolve_summary_policies(
    inspection: Option<&analysis::StatementInspection<'_>>,
    field_count: usize,
    safety: &[Safety],
    snapshot: &Snapshot,
    roles: &HashSet<String>,
) -> Vec<ExpressionPolicy> {
    let resolution = inspection.and_then(|value| value.summary_resolution(field_count));
    (0..field_count)
        .map(|index| {
            if safety.get(index) != Some(&Safety::Summary) {
                return ExpressionPolicy::NotApplicable;
            }
            let Some(resolution) = resolution.as_ref() else {
                return ExpressionPolicy::Opaque;
            };
            let Some(argument) = resolution.fields().get(index) else {
                return ExpressionPolicy::Opaque;
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
/// Returns [`ExpressionPolicy::Opaque`] when an argument is not a bare column, a
/// relation is unqualified, ownership is not unique, or the catalog has never
/// heard of a relation or column. Explicit schema qualification is
/// load-bearing: the proxy does not track `search_path`, and a wrong relation
/// can carry a weaker mask than the relation PostgreSQL actually selected.
fn resolve_summary_source(
    snapshot: &Snapshot,
    relations: &[(String, String)],
    argument: &analysis::SummaryArgument,
    roles: &HashSet<String>,
) -> ExpressionPolicy {
    let analysis::SummaryArgument::BareColumn(column) = argument else {
        return ExpressionPolicy::Opaque;
    };
    let mut owners = 0usize;
    let mut owner: Option<&(String, String)> = None;
    for relation in relations {
        let Some(qualified) = qualify_relation(relation) else {
            return ExpressionPolicy::Opaque;
        };
        // A relation the catalog has never heard of means ownership cannot be
        // ruled out, so nothing is attributed.
        let Some(columns) = snapshot.relation_columns(&qualified) else {
            return ExpressionPolicy::Opaque;
        };
        if columns.iter().any(|c| c.as_str() == column) {
            owners = owners.saturating_add(1);
            owner = Some(relation);
        }
    }
    if owners != 1 {
        return ExpressionPolicy::Opaque;
    }
    let Some(qualified) = owner.and_then(qualify_relation) else {
        return ExpressionPolicy::Opaque;
    };
    let Some(classification) = snapshot.lookup_by_name(&qualified, column) else {
        return ExpressionPolicy::Opaque;
    };
    let spec = classification.for_roles(roles).clone();
    if spec.is_passthrough() {
        ExpressionPolicy::Released
    } else {
        ExpressionPolicy::Masked {
            spec,
            projection: None,
        }
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

    #[allow(clippy::too_many_arguments)]
    fn assemble(
        catalog: Arc<Catalog>,
        unclassified: Unclassified,
        opaque: Opaque,
        summaries: Summaries,
        posture: Posture,
        lineage: Lineage,
        rate_limit: Option<PrincipalRateLimit>,
        max_notices_per_exchange: Option<u32>,
    ) -> Policy {
        Policy {
            catalog,
            masker: ArcSwap::from_pointee(Masker::new(b"k".to_vec())),
            live: ArcSwap::from_pointee(LivePolicy {
                unclassified,
                unclassified_mask: UnclassifiedMask::default(),
                opaque,
                summaries,
                posture,
                system_catalogs: SystemCatalogs::Refuse,
                lineage,
                roles: HashMap::new(),
                require_client_tls: false,
                backend_tls: BackendTls::Disable,
                backend_ca: None,
                rate_limit,
                max_notices_per_exchange,
                tls_cert: None,
                tls_key: None,
            }),
            tls: ArcSwap::from_pointee(None),
            metrics: Arc::new(Metrics::default()),
            identity: ProcessIdentity {
                listen: "127.0.0.1:0".into(),
                backend: "127.0.0.1:1".into(),
                catalog_dsn: String::new(),
                metrics_listen: None,
            },
            epoch: AtomicU64::new(0),
            reloads: AtomicU64::new(0),
            failed_reloads: AtomicU64::new(0),
            last_file_sha: ArcSwap::from_pointee(None),
            reload: tokio::sync::Mutex::new(()),
        }
    }

    pub(crate) fn policy(unclassified: Unclassified, opaque: Opaque) -> Arc<Policy> {
        Arc::new(assemble(
            Arc::new(Catalog::default()),
            unclassified,
            opaque,
            Summaries::Allow,
            Posture::Default,
            Lineage::Refuse,
            None,
            None,
        ))
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
        Arc::new(assemble(
            Arc::new(Catalog::default()),
            unclassified,
            opaque,
            Summaries::Allow,
            Posture::Default,
            Lineage::Allow,
            None,
            None,
        ))
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
        Arc::new(assemble(
            Arc::new(Catalog::default()),
            Unclassified::Allow,
            Opaque::Reject,
            Summaries::Allow,
            Posture::Default,
            Lineage::Refuse,
            Some(PrincipalRateLimit::new(per_minute, burst).unwrap()),
            None,
        ))
    }

    pub(crate) fn policy_with_notice_cap(max: u32) -> Arc<Policy> {
        Arc::new(assemble(
            Arc::new(Catalog::default()),
            Unclassified::Allow,
            Opaque::Reject,
            Summaries::Allow,
            Posture::Default,
            Lineage::Refuse,
            None,
            Some(max),
        ))
    }

    pub(crate) fn policy_with_catalog(
        catalog: Arc<Catalog>,
        unclassified: Unclassified,
        opaque: Opaque,
    ) -> Arc<Policy> {
        Arc::new(assemble(
            catalog,
            unclassified,
            opaque,
            Summaries::Allow,
            Posture::Default,
            Lineage::Refuse,
            None,
            None,
        ))
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
    use std::sync::atomic::Ordering;

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

    fn minimal_config(unclassified: Unclassified) -> Config {
        let unclassified = match unclassified {
            Unclassified::Allow => "allow",
            Unclassified::Mask => "mask",
        };
        toml::from_str(&format!(
            r#"
backend = "127.0.0.1:1"
listen = "127.0.0.1:0"
catalog_dsn = "postgres://unused"
pseudonym_key = "a-long-enough-key"
unclassified = "{unclassified}"
"#
        ))
        .expect("fixture parses")
    }

    #[tokio::test]
    async fn apply_config_updates_live_knobs_without_a_database() {
        let config = minimal_config(Unclassified::Allow);
        let policy = Policy::from_config(&config, Arc::new(Catalog::default())).unwrap();
        let mut next = config.clone();
        next.unclassified = Unclassified::Mask;
        let report = policy
            .apply_config(&next)
            .await
            .expect("live-only reload must not talk to the catalog DSN");
        assert!(
            !report.catalog_re_resolved,
            "unchanged column rules must skip pg_class"
        );
        assert_eq!(policy.unclassified(), Unclassified::Mask);
        assert_eq!(
            policy.generation(),
            2,
            "a live change bumps generation before and after the swap"
        );
    }

    #[tokio::test]
    async fn a_bad_reload_keeps_the_previous_policy() {
        let config = minimal_config(Unclassified::Allow);
        let policy = Policy::from_config(&config, Arc::new(Catalog::default())).unwrap();
        let generation = policy.generation();
        assert!(policy
            .reload_from_path("/no/such/pgmask.toml")
            .await
            .is_err());
        assert_eq!(policy.unclassified(), Unclassified::Allow);
        assert_eq!(policy.generation(), generation);
        assert!(policy.failed_reloads.load(Ordering::Relaxed) >= 1);
    }

    #[tokio::test]
    async fn a_file_rewritten_after_parse_is_not_skipped_on_sighup() {
        let dir = std::env::temp_dir().join(format!("pgmask-reload-sha-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("catalog.toml");
        let first = r#"
backend = "127.0.0.1:1"
listen = "127.0.0.1:0"
catalog_dsn = "postgres://unused"
pseudonym_key = "a-long-enough-key"
unclassified = "allow"
"#;
        std::fs::write(&path, first).unwrap();
        let (config, bytes) = Config::load_with_bytes(path.to_str().unwrap()).unwrap();
        let policy = Policy::from_config(&config, Arc::new(Catalog::default())).unwrap();
        policy.remember_file_bytes(&bytes);
        std::fs::write(&path, first.replace("allow", "mask")).unwrap();
        let report = policy
            .reload_from_path(path.to_str().unwrap())
            .await
            .unwrap();
        assert!(
            !report.unchanged,
            "the SHA of the parsed boot bytes must not skip a rewritten file"
        );
        assert_eq!(policy.unclassified(), Unclassified::Mask);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A SIGHUP with no edit is a no-op, and it must still count as a reload:
    /// it is the certificate-rotation path, and an operator who sees neither a
    /// log line nor a counter cannot tell it from a signal that went nowhere.
    #[tokio::test]
    async fn an_unedited_file_reports_unchanged_and_still_counts() {
        let dir = std::env::temp_dir().join(format!("pgmask-reload-same-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("catalog.toml");
        std::fs::write(
            &path,
            r#"
backend = "127.0.0.1:1"
listen = "127.0.0.1:0"
catalog_dsn = "postgres://unused"
pseudonym_key = "a-long-enough-key"
unclassified = "allow"
"#,
        )
        .unwrap();
        let (config, bytes) = Config::load_with_bytes(path.to_str().unwrap()).unwrap();
        let policy = Policy::from_config(&config, Arc::new(Catalog::default())).unwrap();
        policy.remember_file_bytes(&bytes);
        let generation = policy.generation();

        let report = policy
            .reload_from_path(path.to_str().unwrap())
            .await
            .unwrap();
        assert!(report.unchanged, "identical bytes must short-circuit");
        assert!(
            !report.catalog_re_resolved,
            "an unchanged file must not pay a pg_class round-trip"
        );
        assert_eq!(
            policy.generation(),
            generation,
            "a no-op reload must not invalidate cached plans"
        );
        assert_eq!(
            policy.reloads.load(Ordering::Relaxed),
            1,
            "a no-op reload is still an observed reload"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn listen_change_is_reported_and_other_knobs_still_apply() {
        let config = minimal_config(Unclassified::Allow);
        let policy = Policy::from_config(&config, Arc::new(Catalog::default())).unwrap();
        let mut next = config.clone();
        next.listen = "0.0.0.0:6432".into();
        next.unclassified = Unclassified::Mask;
        let report = policy.apply_config(&next).await.unwrap();
        assert!(
            report.restart_required.contains(&"listen"),
            "bind address cannot change in process: {:?}",
            report.restart_required
        );
        assert_eq!(policy.unclassified(), Unclassified::Mask);
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
                    expression: &[],
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
                    expression: &[],
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
                    expression: &[],
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
                    expression: &[],
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
                    expression: &[],
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
                    expression: &[],
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
        let p = policy(Unclassified::Mask, Opaque::Reject);
        p.set_unclassified_mask_for_test(UnclassifiedMask::Null);
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
                    expression: &[],
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
                    expression: &[],
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
                    expression: &[],
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
                    expression: &[],
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
                    expression: &[],
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
                    expression: &[ExpressionPolicy::Masked {
                        spec: MaskSpec::new(Mask::NumericBucket),
                        projection: None,
                    }],
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
                    expression: &[ExpressionPolicy::Masked {
                        spec: MaskSpec::new(Mask::NumericBucket),
                        projection: None,
                    }],
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
                    expression: &[],
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
                    expression: &[],
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
            ExpressionPolicy::Opaque,
            "the backend may resolve payroll through search_path to another schema"
        );
    }

    #[test]
    fn text_mask_on_a_non_text_column_is_refused_at_plan_time() {
        let mut snapshot = crate::catalog::Snapshot::default();
        snapshot.insert_for_test(16391, 1, Mask::Pseudonym, "demo.t.id");
        let p = policy_with_catalog(
            Arc::new(Catalog::from_snapshot_for_test(snapshot)),
            Unclassified::Allow,
            Opaque::Reject,
        );
        // int4, not a text type: pseudonym rewrites values as text.
        let err = p
            .plan_for(
                &p.catalog.snapshot(),
                &[field("id", 16391, 1, 23)],
                &HashSet::new(),
                &FieldAnalysis {
                    safety: &[],
                    lineage: &[],
                    expression: &[],
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
                    expression: &[ExpressionPolicy::Masked {
                        spec: MaskSpec::new(Mask::NumericBucket),
                        projection: None,
                    }],
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
                    expression: &[ExpressionPolicy::Opaque],
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
                    expression: &[ExpressionPolicy::Released],
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
