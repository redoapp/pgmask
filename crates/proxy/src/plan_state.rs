//! Extended-query plan lifecycle.
//!
//! PostgreSQL names prepared statements and portals independently, permits
//! pipelining across `Sync` boundaries, and answers `Describe` asynchronously.
//! Every map and queue needed to preserve those relationships lives here so
//! invalidation and ordering rules cannot drift across session message arms.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use bytes::Bytes;

use crate::mask::MaskSpec;
use crate::protocol::{self, DescribeTarget};

/// What to do with one output field.
#[derive(Debug, Clone)]
pub(crate) struct FieldPlan {
    pub(crate) spec: MaskSpec,
    pub(crate) type_oid: u32,
    pub(crate) format: i16,
}

pub(crate) type Plan = Arc<Vec<FieldPlan>>;

/// A `Describe` the backend has not answered yet, and the SQL it was for.
struct PendingDescribe {
    target: DescribeTarget,
    sql: Option<String>,
    /// How many `Sync`s the client had sent when this was issued.
    ///
    /// An `ErrorResponse` makes the backend skip every remaining message up to
    /// the next `Sync`, so exactly the Describes sharing the failing one's
    /// epoch are dead. Anything after that `Sync` remains live.
    epoch: u64,
}

/// A frontend mutation that has not yet received its backend acknowledgement.
///
/// Parse and Bind state is provisionally useful to later pipelined messages,
/// but must be invalidated if the backend rejects the command. Otherwise the
/// proxy and backend can assign different SQL or plans to the same name.
struct PendingMutation {
    name: Bytes,
    epoch: u64,
}

/// All state that binds SQL, statements, portals, descriptions, and row plans.
#[derive(Default)]
pub(crate) struct PlanState {
    statement_plans: HashMap<Bytes, Plan>,
    statement_sql: HashMap<Bytes, String>,
    portal_statement: HashMap<Bytes, Bytes>,
    portal_plans: HashMap<Bytes, Plan>,
    active_plan: Option<Plan>,
    active_epoch: Option<u64>,
    pending_describes: VecDeque<PendingDescribe>,
    pending_parses: VecDeque<PendingMutation>,
    pending_binds: VecDeque<PendingMutation>,
    simple_sql: Option<String>,
    sync_epoch: u64,
    /// Catalog generation the cached plans were built under.
    generation: u64,
}

impl PlanState {
    /// Drop cached plans built before a catalog refresh.
    ///
    /// A plan is a decision made against one snapshot, and statement and portal
    /// plans outlive the result set they were described for — that is the point
    /// of caching them.
    ///
    /// A refresh does not re-read the catalog *file* (that needs a restart), so
    /// this is not about an operator editing a rule. It re-resolves names to
    /// OIDs, and DDL moves those: `DROP TABLE; CREATE TABLE` gives a new OID,
    /// and PostgreSQL reuses OIDs. A plan cached across that boundary applies
    /// the previous mapping's classification — which, when an OID has been
    /// recycled onto a different relation, is the wrong column's mask.
    ///
    /// The in-flight `active_plan` is deliberately kept: its rows are already
    /// being described and served, and that is bounded by one result set. What
    /// is dropped is everything a *later* Bind or Execute would reuse, so the
    /// next one has no plan and fails closed until a fresh Describe rebuilds
    /// it against the new snapshot.
    pub(crate) fn invalidate_if_stale(&mut self, current: u64) {
        if self.generation == current {
            return;
        }
        self.generation = current;
        self.statement_plans.clear();
        self.portal_plans.clear();
    }

    pub(crate) fn active_plan(&self) -> Option<Plan> {
        self.active_plan.clone()
    }

    pub(crate) fn clear_active(&mut self) {
        self.active_plan = None;
        self.active_epoch = None;
    }

    pub(crate) fn begin_simple_query(&mut self, sql: Option<String>) {
        self.active_plan = None;
        self.active_epoch = None;
        self.pending_describes.clear();
        self.simple_sql = sql;
    }

    pub(crate) fn parse(&mut self, name: Bytes, sql: String) {
        // A genuinely different statement invalidates every plan derived from
        // the old SQL. Some drivers re-Parse the unnamed statement with the
        // same SQL and reuse its described result metadata, which remains valid.
        if self.statement_sql.get(&name) != Some(&sql) {
            self.statement_plans.remove(&name);
            let stale_portals: Vec<Bytes> = self
                .portal_statement
                .iter()
                .filter(|(_, statement)| **statement == name)
                .map(|(portal, _)| portal.clone())
                .collect();
            for portal in stale_portals {
                self.portal_plans.remove(&portal);
            }
        }
        self.statement_sql.insert(name.clone(), sql);
        self.pending_parses.push_back(PendingMutation {
            name,
            epoch: self.sync_epoch,
        });
    }

    pub(crate) fn bind(&mut self, portal: Bytes, statement: Bytes, formats: Option<Vec<i16>>) {
        self.portal_statement
            .insert(portal.clone(), statement.clone());
        self.pending_binds.push_back(PendingMutation {
            name: portal.clone(),
            epoch: self.sync_epoch,
        });
        let Some(statement_plan) = self.statement_plans.get(&statement) else {
            self.portal_plans.remove(&portal);
            return;
        };

        // Describe(Statement) reports text because result formats are not chosen
        // until Bind. Re-stamp the plan with this portal's actual formats.
        let portal_plan = match formats {
            Some(formats) => Arc::new(
                statement_plan
                    .iter()
                    .enumerate()
                    .map(|(index, field)| FieldPlan {
                        format: protocol::format_for(&formats, index),
                        ..field.clone()
                    })
                    .collect(),
            ),
            // An unparseable Bind keeps the described format. A wrong format
            // then fails decoding and refuses the result set rather than guessing.
            None => statement_plan.clone(),
        };
        self.portal_plans.insert(portal, portal_plan);
    }

    pub(crate) fn describe(&mut self, target: DescribeTarget) {
        let sql = match &target {
            DescribeTarget::Statement(name) => self.statement_sql.get(name).cloned(),
            DescribeTarget::Portal(portal) => self
                .portal_statement
                .get(portal)
                .and_then(|statement| self.statement_sql.get(statement))
                .cloned(),
        };
        self.pending_describes.push_back(PendingDescribe {
            target,
            sql,
            epoch: self.sync_epoch,
        });
    }

    pub(crate) fn execute(&mut self, portal: &Bytes) {
        self.active_plan = self.portal_plans.get(portal).cloned();
        self.active_epoch = Some(self.sync_epoch);
    }

    /// Mirror PostgreSQL's resource lifetime after a frontend `Close`.
    /// Closing a statement also closes every portal constructed from it.
    ///
    /// The active plan deliberately survives: an Execute may precede its Close
    /// in the same pipeline, and those rows arrive before `CloseComplete`.
    pub(crate) fn close(&mut self, target: DescribeTarget) {
        match target {
            DescribeTarget::Statement(statement) => {
                self.statement_sql.remove(&statement);
                self.statement_plans.remove(&statement);

                let portals: Vec<Bytes> = self
                    .portal_statement
                    .iter()
                    .filter(|(_, bound_statement)| **bound_statement == statement)
                    .map(|(portal, _)| portal.clone())
                    .collect();
                for portal in portals {
                    self.portal_statement.remove(&portal);
                    self.portal_plans.remove(&portal);
                }
            }
            DescribeTarget::Portal(portal) => {
                self.portal_statement.remove(&portal);
                self.portal_plans.remove(&portal);
            }
        }
    }

    pub(crate) fn sync(&mut self) {
        self.sync_epoch = self.sync_epoch.saturating_add(1);
    }

    pub(crate) fn finish_parse(&mut self) {
        self.pending_parses.pop_front();
    }

    pub(crate) fn finish_bind(&mut self) {
        self.pending_binds.pop_front();
    }

    /// Epoch whose backend traffic must be suppressed after a local refusal.
    pub(crate) fn rejection_epoch(&self) -> u64 {
        self.pending_describes
            .front()
            .map_or(self.active_epoch.unwrap_or(self.sync_epoch), |pending| {
                pending.epoch
            })
    }

    /// Finish one locally suppressed exchange without deleting later
    /// pipelined work. Unlike [`discard_failed_epoch`](Self::discard_failed_epoch),
    /// the backend did execute these mutations; only their responses were
    /// suppressed, so their provisional state remains valid.
    pub(crate) fn finish_suppressed_epoch(&mut self, epoch: u64) {
        self.pending_describes
            .retain(|pending| pending.epoch != epoch);
        self.pending_parses.retain(|pending| pending.epoch != epoch);
        self.pending_binds.retain(|pending| pending.epoch != epoch);
    }

    /// Remove provisional state from a failed exchange while preserving later
    /// pipelined exchanges that have already crossed a `Sync`.
    pub(crate) fn discard_failed_epoch(&mut self) {
        let failed_epoch = [
            self.pending_describes.front().map(|p| p.epoch),
            self.pending_parses.front().map(|p| p.epoch),
            self.pending_binds.front().map(|p| p.epoch),
        ]
        .into_iter()
        .flatten()
        .min();
        let Some(failed_epoch) = failed_epoch else {
            return;
        };

        // A later pipelined epoch may already have reused the same name. Keep
        // its provisional state; its own acknowledgement or error will decide
        // whether it survives.
        let later_statements: HashSet<Bytes> = self
            .pending_parses
            .iter()
            .filter(|pending| pending.epoch > failed_epoch)
            .map(|pending| pending.name.clone())
            .collect();
        let failed_statements: Vec<Bytes> = self
            .pending_parses
            .iter()
            .filter(|pending| pending.epoch == failed_epoch)
            .map(|pending| pending.name.clone())
            .collect();
        for statement in failed_statements {
            if !later_statements.contains(&statement) {
                self.statement_sql.remove(&statement);
                self.statement_plans.remove(&statement);
            }
        }

        let later_portals: HashSet<Bytes> = self
            .pending_binds
            .iter()
            .filter(|pending| pending.epoch > failed_epoch)
            .map(|pending| pending.name.clone())
            .collect();
        let failed_portals: Vec<Bytes> = self
            .pending_binds
            .iter()
            .filter(|pending| pending.epoch == failed_epoch)
            .map(|pending| pending.name.clone())
            .collect();
        for portal in failed_portals {
            if !later_portals.contains(&portal) {
                self.portal_statement.remove(&portal);
                self.portal_plans.remove(&portal);
            }
        }

        self.pending_describes
            .retain(|pending| pending.epoch != failed_epoch);
        self.pending_parses
            .retain(|pending| pending.epoch != failed_epoch);
        self.pending_binds
            .retain(|pending| pending.epoch != failed_epoch);
    }

    pub(crate) fn finish_no_data(&mut self) {
        self.pending_describes.pop_front();
    }

    pub(crate) fn described_sql(&self) -> Option<String> {
        self.pending_describes
            .front()
            .and_then(|pending| pending.sql.clone())
            .or_else(|| self.simple_sql.clone())
    }

    pub(crate) fn discard_description(&mut self) {
        self.pending_describes.pop_front();
    }

    /// Bind a completed plan to the described target and activate it for the
    /// DataRows that follow the RowDescription.
    pub(crate) fn finish_description(&mut self, plan: Plan) {
        let pending = self.pending_describes.pop_front();
        let epoch = pending
            .as_ref()
            .map_or(self.sync_epoch, |pending| pending.epoch);
        match pending.map(|p| p.target) {
            Some(DescribeTarget::Statement(name)) => {
                self.statement_plans.insert(name, plan.clone());
            }
            Some(DescribeTarget::Portal(name)) => {
                self.portal_plans.insert(name, plan.clone());
            }
            None => {}
        }
        self.active_plan = Some(plan);
        self.active_epoch = Some(epoch);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;
    use crate::mask::Mask;

    fn plan() -> Plan {
        Arc::new(vec![FieldPlan {
            spec: MaskSpec::new(Mask::None),
            type_oid: 25,
            format: 0,
        }])
    }

    fn name(value: &'static str) -> Bytes {
        Bytes::from_static(value.as_bytes())
    }

    /// A catalog refresh drops every cached plan.
    ///
    /// A refresh re-resolves names to OIDs, and DDL moves those. A plan cached
    /// across a refresh applies the previous mapping — which, once an OID has
    /// been recycled onto another relation, is a different column's mask.
    /// Every other DDL direction already failed closed; this was the one that
    /// did not.
    #[test]
    fn a_catalog_refresh_invalidates_cached_plans() {
        let mut state = PlanState::default();
        state.parse(name("s"), "SELECT secret FROM t".into());
        state.describe(DescribeTarget::Statement(name("s")));
        state.finish_description(plan());

        // Same generation: the cached plan is still reusable.
        state.invalidate_if_stale(0);
        state.bind(name("p"), name("s"), None);
        state.execute(&name("p"));
        assert!(
            state.active_plan().is_some(),
            "no refresh, so the plan stands"
        );

        // The catalog refreshed underneath the session.
        state.invalidate_if_stale(1);
        state.bind(name("p"), name("s"), None);
        state.execute(&name("p"));
        assert!(
            state.active_plan().is_none(),
            "a plan built against the previous snapshot must not be reused"
        );

        // A fresh Describe rebuilds it against the new snapshot.
        state.describe(DescribeTarget::Statement(name("s")));
        state.finish_description(plan());
        state.bind(name("p"), name("s"), None);
        state.execute(&name("p"));
        assert!(
            state.active_plan().is_some(),
            "re-describing must restore it"
        );
    }

    #[test]
    fn different_sql_invalidates_but_identical_sql_preserves_a_plan() {
        let mut state = PlanState::default();
        state.parse(name("s"), "SELECT 1".into());
        state.describe(DescribeTarget::Statement(name("s")));
        state.finish_description(plan());

        state.parse(name("s"), "SELECT 1".into());
        state.bind(name("p"), name("s"), Some(vec![1]));
        state.execute(&name("p"));
        assert_eq!(state.active_plan().unwrap().first().unwrap().format, 1);

        state.parse(name("s"), "SELECT secret FROM t".into());
        state.bind(name("p"), name("s"), Some(vec![0]));
        state.execute(&name("p"));
        assert!(state.active_plan().is_none());
    }

    #[test]
    fn a_failed_epoch_does_not_discard_a_later_pipelined_describe() {
        let mut state = PlanState::default();
        state.parse(name("bad"), "SELECT bad".into());
        state.describe(DescribeTarget::Statement(name("bad")));
        state.sync();
        state.parse(name("good"), "SELECT 1".into());
        state.describe(DescribeTarget::Statement(name("good")));

        state.discard_failed_epoch();
        assert_eq!(state.described_sql().as_deref(), Some("SELECT 1"));
    }

    #[test]
    fn a_locally_suppressed_epoch_preserves_later_pipelined_describes() {
        let mut state = PlanState::default();
        state.parse(name("reject"), "SELECT lower(secret) FROM t".into());
        state.describe(DescribeTarget::Statement(name("reject")));
        state.sync();
        state.parse(name("later"), "SELECT 1".into());
        state.describe(DescribeTarget::Statement(name("later")));

        state.finish_suppressed_epoch(0);
        assert_eq!(state.described_sql().as_deref(), Some("SELECT 1"));
    }

    #[test]
    fn a_rejected_reparse_cannot_replace_the_backends_sql_identity() {
        let mut state = PlanState::default();
        state.parse(name("s"), "SELECT lower(secret) FROM t".into());
        state.finish_parse();

        state.parse(name("s"), "SELECT 1".into());
        state.sync();
        state.discard_failed_epoch();
        state.describe(DescribeTarget::Statement(name("s")));

        assert_eq!(
            state.described_sql(),
            None,
            "after a rejected Parse, unknown is safer than analyzing the old backend statement as the new SQL"
        );
    }

    #[test]
    fn close_releases_proxy_state_without_discarding_in_flight_rows() {
        let mut state = PlanState::default();
        state.parse(name("s"), "SELECT 1".into());
        state.describe(DescribeTarget::Statement(name("s")));
        state.finish_description(plan());
        state.bind(name("p"), name("s"), Some(vec![0]));
        state.execute(&name("p"));

        state.close(DescribeTarget::Statement(name("s")));
        assert!(
            state.active_plan().is_some(),
            "an Execute pipelined before Close still has rows in flight"
        );

        state.clear_active();
        state.execute(&name("p"));
        assert!(
            state.active_plan().is_none(),
            "closing a statement must implicitly release its portals"
        );
    }
}
