//! Statement-class gates the session runs before a query reaches the backend.

use pg_query::protobuf::node::Node as NodeEnum;

use super::names::{func_call_name_parts, is_trusted_function_name};
use super::walk::tree_any;
use super::StatementInspection;

/// `DO` / `CALL` / `CREATE FUNCTION` (and `CREATE PROCEDURE`) — they run or
/// install PL/pgSQL without a maskable projection, which is how the timing and
/// exception-presence oracles under `posture = "hostile"` still worked after
/// notice caps. Exploration does not need them; refuse the statement class.
pub fn is_procedural_statement(sql: &str) -> bool {
    let inspection = StatementInspection::new(sql);
    let Some(parsed) = inspection.parsed() else {
        return false;
    };
    tree_any(parsed, |node| {
        matches!(
            node.node.as_ref(),
            Some(NodeEnum::DoStmt(_))
                | Some(NodeEnum::CallStmt(_))
                | Some(NodeEnum::CreateFunctionStmt(_))
        )
    })
}

/// SQL-level `PREPARE` / `EXECUTE` / `DEALLOCATE` and `DECLARE` / `FETCH` /
/// `CLOSE`. A second copy of the extended protocol (`Parse`/`Bind`/`Execute`
/// and named portals). Walked from the statement root so `EXPLAIN PREPARE`
/// is the same class. Analysts keep ordinary `SELECT` — including
/// `SELECT … FETCH FIRST n ROWS`, which is a `SelectStmt` limit, not a
/// `FetchStmt` — and protocol Parse/Bind.
///
/// Parse failure returns false, same as [`is_write_statement`]; other gates
/// still apply. Refused on every posture, not only hostile.
pub fn is_sql_prepare_or_cursor(sql: &str) -> bool {
    StatementInspection::new(sql).is_sql_prepare_or_cursor()
}

pub(crate) fn is_sql_prepare_or_cursor_inspected(inspection: &StatementInspection<'_>) -> bool {
    let Some(parsed) = inspection.parsed() else {
        return false;
    };
    tree_any(parsed, |node| {
        matches!(
            node.node.as_ref(),
            Some(NodeEnum::PrepareStmt(_))
                | Some(NodeEnum::ExecuteStmt(_))
                | Some(NodeEnum::DeallocateStmt(_))
                | Some(NodeEnum::DeclareCursorStmt(_))
                | Some(NodeEnum::FetchStmt(_))
                | Some(NodeEnum::ClosePortalStmt(_))
        )
    })
}

/// Anything that is not on the read-only allowlist.
///
/// Fail-closed: every `*Stmt` node must be explicitly permitted, or the
/// statement is refused. A denylist missed `CREATE VIEW` / `LOAD` /
/// `CHECKPOINT` (and would miss the next DDL variant pg_query adds). pgmask
/// is a read-only masking proxy — writes and admin DDL are refused on every
/// posture, not only hostile.
///
/// SQL `PREPARE`/`DECLARE` and friends stay on this allowlist so they are
/// not bucketed as writes; [`is_sql_prepare_or_cursor`] refuses them with
/// a dedicated error.
pub fn is_write_statement(sql: &str) -> bool {
    StatementInspection::new(sql).is_write_statement()
}

pub(crate) fn is_write_statement_inspected(inspection: &StatementInspection<'_>) -> bool {
    let Some(parsed) = inspection.parsed() else {
        return false;
    };
    tree_any(parsed, node_is_write)
}

fn node_is_write(node: &pg_query::protobuf::Node) -> bool {
    match node.node.as_ref() {
        // --- read-only / session allowlist ---------------------------------
        Some(NodeEnum::SelectStmt(select)) => {
            // Row locks and SELECT INTO are write-adjacent.
            select.into_clause.is_some() || !select.locking_clause.is_empty()
        }
        Some(NodeEnum::SetOperationStmt(_))
        | Some(NodeEnum::ExplainStmt(_))
        | Some(NodeEnum::VariableSetStmt(_))
        | Some(NodeEnum::VariableShowStmt(_))
        | Some(NodeEnum::TransactionStmt(_))
        | Some(NodeEnum::PrepareStmt(_))
        | Some(NodeEnum::ExecuteStmt(_))
        | Some(NodeEnum::DeallocateStmt(_))
        | Some(NodeEnum::DiscardStmt(_))
        | Some(NodeEnum::DeclareCursorStmt(_))
        | Some(NodeEnum::FetchStmt(_))
        | Some(NodeEnum::ClosePortalStmt(_))
        | Some(NodeEnum::ConstraintsSetStmt(_))
        | Some(NodeEnum::RawStmt(_)) => false,

        // --- every other statement class is refused ------------------------
        Some(NodeEnum::InsertStmt(_))
        | Some(NodeEnum::UpdateStmt(_))
        | Some(NodeEnum::DeleteStmt(_))
        | Some(NodeEnum::MergeStmt(_))
        | Some(NodeEnum::TruncateStmt(_))
        | Some(NodeEnum::CopyStmt(_))
        | Some(NodeEnum::ViewStmt(_))
        | Some(NodeEnum::LoadStmt(_))
        | Some(NodeEnum::CheckPointStmt(_))
        | Some(NodeEnum::CreateStmt(_))
        | Some(NodeEnum::CreateTableAsStmt(_))
        | Some(NodeEnum::CreateSchemaStmt(_))
        | Some(NodeEnum::CreateSeqStmt(_))
        | Some(NodeEnum::CreateForeignTableStmt(_))
        | Some(NodeEnum::CreateFunctionStmt(_))
        | Some(NodeEnum::CreateTrigStmt(_))
        | Some(NodeEnum::CreateRoleStmt(_))
        | Some(NodeEnum::CreatedbStmt(_))
        | Some(NodeEnum::CreateEnumStmt(_))
        | Some(NodeEnum::CreateDomainStmt(_))
        | Some(NodeEnum::CreateExtensionStmt(_))
        | Some(NodeEnum::CreatePlangStmt(_))
        | Some(NodeEnum::CreateConversionStmt(_))
        | Some(NodeEnum::CreateCastStmt(_))
        | Some(NodeEnum::CreateOpClassStmt(_))
        | Some(NodeEnum::CreateOpFamilyStmt(_))
        | Some(NodeEnum::CreateTableSpaceStmt(_))
        | Some(NodeEnum::CreateFdwStmt(_))
        | Some(NodeEnum::CreateForeignServerStmt(_))
        | Some(NodeEnum::CreateUserMappingStmt(_))
        | Some(NodeEnum::CreateEventTrigStmt(_))
        | Some(NodeEnum::CreatePolicyStmt(_))
        | Some(NodeEnum::CreateTransformStmt(_))
        | Some(NodeEnum::CreateAmStmt(_))
        | Some(NodeEnum::CreatePublicationStmt(_))
        | Some(NodeEnum::CreateSubscriptionStmt(_))
        | Some(NodeEnum::CreateStatsStmt(_))
        | Some(NodeEnum::CreateRangeStmt(_))
        | Some(NodeEnum::CompositeTypeStmt(_))
        | Some(NodeEnum::DefineStmt(_))
        | Some(NodeEnum::IndexStmt(_))
        | Some(NodeEnum::RuleStmt(_))
        | Some(NodeEnum::DropStmt(_))
        | Some(NodeEnum::DropRoleStmt(_))
        | Some(NodeEnum::DropdbStmt(_))
        | Some(NodeEnum::DropTableSpaceStmt(_))
        | Some(NodeEnum::DropUserMappingStmt(_))
        | Some(NodeEnum::DropOwnedStmt(_))
        | Some(NodeEnum::DropSubscriptionStmt(_))
        | Some(NodeEnum::AlterTableStmt(_))
        | Some(NodeEnum::AlterSeqStmt(_))
        | Some(NodeEnum::AlterRoleStmt(_))
        | Some(NodeEnum::AlterDatabaseStmt(_))
        | Some(NodeEnum::AlterDatabaseSetStmt(_))
        | Some(NodeEnum::AlterDatabaseRefreshCollStmt(_))
        | Some(NodeEnum::AlterFunctionStmt(_))
        | Some(NodeEnum::AlterOwnerStmt(_))
        | Some(NodeEnum::AlterObjectSchemaStmt(_))
        | Some(NodeEnum::AlterObjectDependsStmt(_))
        | Some(NodeEnum::AlterEnumStmt(_))
        | Some(NodeEnum::AlterSystemStmt(_))
        | Some(NodeEnum::AlterDomainStmt(_))
        | Some(NodeEnum::AlterDefaultPrivilegesStmt(_))
        | Some(NodeEnum::AlterOpFamilyStmt(_))
        | Some(NodeEnum::AlterOperatorStmt(_))
        | Some(NodeEnum::AlterTypeStmt(_))
        | Some(NodeEnum::AlterRoleSetStmt(_))
        | Some(NodeEnum::AlterTsdictionaryStmt(_))
        | Some(NodeEnum::AlterTsconfigurationStmt(_))
        | Some(NodeEnum::AlterFdwStmt(_))
        | Some(NodeEnum::AlterForeignServerStmt(_))
        | Some(NodeEnum::AlterUserMappingStmt(_))
        | Some(NodeEnum::AlterTableSpaceOptionsStmt(_))
        | Some(NodeEnum::AlterTableMoveAllStmt(_))
        | Some(NodeEnum::AlterExtensionStmt(_))
        | Some(NodeEnum::AlterExtensionContentsStmt(_))
        | Some(NodeEnum::AlterEventTrigStmt(_))
        | Some(NodeEnum::AlterPolicyStmt(_))
        | Some(NodeEnum::AlterPublicationStmt(_))
        | Some(NodeEnum::AlterSubscriptionStmt(_))
        | Some(NodeEnum::AlterStatsStmt(_))
        | Some(NodeEnum::AlterCollationStmt(_))
        | Some(NodeEnum::RenameStmt(_))
        | Some(NodeEnum::GrantStmt(_))
        | Some(NodeEnum::GrantRoleStmt(_))
        | Some(NodeEnum::ReassignOwnedStmt(_))
        | Some(NodeEnum::CommentStmt(_))
        | Some(NodeEnum::SecLabelStmt(_))
        | Some(NodeEnum::ImportForeignSchemaStmt(_))
        | Some(NodeEnum::ReplicaIdentityStmt(_))
        | Some(NodeEnum::VacuumStmt(_))
        | Some(NodeEnum::ReindexStmt(_))
        | Some(NodeEnum::ClusterStmt(_))
        | Some(NodeEnum::RefreshMatViewStmt(_))
        | Some(NodeEnum::LockStmt(_))
        | Some(NodeEnum::DoStmt(_))
        | Some(NodeEnum::CallStmt(_))
        | Some(NodeEnum::NotifyStmt(_))
        | Some(NodeEnum::ListenStmt(_))
        | Some(NodeEnum::UnlistenStmt(_))
        | Some(NodeEnum::ReturnStmt(_))
        | Some(NodeEnum::PlassignStmt(_)) => true,

        // Expression / type / utility nodes inside an allowed statement.
        _ => false,
    }
}

/// A function call that is not on the trusted `pg_catalog` allowlist.
///
/// Schema-qualified calls outside `pg_catalog` (e.g. `demo.sleep_if`) are how a
/// preinstalled PL/pgSQL function still ran under read-only + hostile: the
/// return value was opaque-refused, but timing / side effects happened first.
/// Unqualified names must appear on the same allowlists `classify` already
/// trusts; everything else is refused before the backend sees it.
///
/// Metadata-only catalog queries are exempt — they need `format_type` and
/// friends, and [`crate::analysis::reads_only_server_metadata`] already gates that path
/// (target-list functions are an allowlist of helpers / trusted names).
pub fn calls_untrusted_function(sql: &str) -> bool {
    StatementInspection::new(sql).calls_untrusted_function()
}

pub(crate) fn calls_untrusted_function_inspected(inspection: &StatementInspection<'_>) -> bool {
    if inspection.reads_only_server_metadata() {
        return false;
    }
    let Some(parsed) = inspection.parsed() else {
        return false;
    };
    tree_any(parsed, |node| {
        matches!(
            node.node.as_ref(),
            Some(NodeEnum::FuncCall(call)) if !func_call_is_trusted(call)
        )
    })
}

fn func_call_is_trusted(call: &pg_query::protobuf::FuncCall) -> bool {
    let Some(parts) = func_call_name_parts(call) else {
        return false;
    };
    let name = match parts.as_slice() {
        [name] => name.as_str(),
        [schema, name] if schema == "pg_catalog" => name.as_str(),
        _ => return false,
    };
    is_trusted_function_name(name)
}
