# Changelog

## 0.1.99 — structure-aware JSON and JSONB masking

- Add `mask = "json"` for classified `json` and `jsonb` columns. RFC 6901 JSON
  Pointer policies inherit through their subtree; more-specific paths override
  parents, so one release rule can cover an evolving public object while
  narrow child rules still redact sensitive fields.
- Every unmatched scalar defaults to JSON `null`; an operator may explicitly
  choose `json_unmatched = "none"` when unmentioned values are intentionally
  public. A configured mask/type mismatch, malformed JSON, or unknown
  binary-jsonb version refuses the result set.
- Add `*` array-element policies, so `/items/*/account_id` masks every item
  without enumerating indices; an exact index wins over the wildcard. Add the
  opt-in `json_unmatched = "type-placeholders"` debugging policy, which
  retains scalar types as `""`, `0`, `false`, and `null` while withholding
  values. One enum now owns all unmatched-leaf behavior (`null`,
  `type-placeholders`, or `none`) instead of two conflicting settings.
  Equally-specific overlapping wildcard policies are rejected at config load
  rather than resolved by TOML order.
- Compile JSON Pointer rules into a trie at catalog load, so walking a node
  follows only exact-key and array-wildcard edges instead of scanning every
  configured rule. Add per-column `json_max_bytes` (1 MiB default) and
  `json_max_depth` (64 default, maximum 128); values over either limit refuse
  before `serde_json` parses or allocates the document tree.
- Attribute literal JSON extracts (`->`, `->>`, `#>`/`#>>`, JSONB subscripting,
  `json[b]_extract_path[_text]`) of a schema-qualified classified column.
  The stored column's pointer policy is applied to the extract; a text extract
  of a node that still has child pointer policies is refused because the
  backend has already serialized the subtree. JSONPath, constructors,
  aggregates, and dynamic keys stay opaque.
- Split JSON masking, extract parsing, extract policy, and catalog pointer
  validation into their own modules so those seams stay reviewable as the
  walker and allowlist grow.
- Keep SQL attribution separate from JSON navigation. Integer `-> 0` is proven
  array navigation; quoted `-> '0'` is object navigation. Text-path segments
  from `#>` / `#>>` and `json[b]_extract_path[_text]` remain ambiguous.
  JSONB subscripts are also ambiguous: PostgreSQL resolves both `[0]` and
  `['0']` from the runtime parent, selecting index 0 under an array and key
  `"0"` under an object. An ambiguous segment that could enter a `*` policy
  refuses instead of letting syntax choose an array-only release. Summaries
  and JSON extracts
  now enter `plan_for` through one resolved-expression policy slot rather than
  a feature-specific fallback ladder.
- Keep extract provenance out of reusable column policy. `MaskSpec` no longer
  carries a hidden `json_path_prefix`; `FieldPlan` carries an explicit
  `JsonProjection` only for document extracts, and the masker receives it as
  execution context. Add a live-Postgres SQL surface matrix covering scalar
  and document operators, function forms, aliases, joins, views, wrappers,
  binary results, ambiguous text paths, CTEs/subqueries, reshaping, set
  operations, and hostile-posture predicate refusal.
- Align the outer safety classifier with extract attribution for `COLLATE`.
  The extract parser already peeled a collation wrapper, but `classify` did
  not, so a valid `(payload->>'public') COLLATE "C"` projection was refused
  despite having the same output bytes and source policy. The live SQL matrix
  found and now pins that cross-layer drift.
- Document JSON pointer inheritance, array wildcards, type placeholders, and
  which SQL shapes are served versus refused in `docs/json-masking.md`.
- Support both pgwire formats. Text values are parsed directly; binary `jsonb`
  validates and preserves PostgreSQL's version byte. Real-Postgres poison
  controls prove the same text and binary rows expose canaries when released,
  and that no canary crosses under the JSON policy. Extraction, construction,
  aggregates, set operations, and COPY of classified JSON refuse; aliases,
  joins, CTEs, subqueries, views, and pipelined portals stay masked on the
  wire. Binary `json` (no version byte) is covered alongside `jsonb`.
- `scripts/test-integration.sh` starts a local trust Postgres when `podman`
  is absent, so the adversarial and resilience suites run on Cloud Agent
  VMs that have host `postgresql` packages but no container runtime.
- Give table-driven raw-wire SQL cases stable names and isolate each case's
  diagnostics to the bytes received for that query, while retaining the full
  connection transcript for the canary audit. JSON and COPY matrices reuse one
  proxy instead of paying setup cost per row. Ordinary and CI `cargo nextest`
  runs now share the serial Postgres test group. This exposed and fixes a
  vacuous dynamic-key case whose nonexistent column produced PostgreSQL 42703;
  the old cumulative buffer mistook an earlier `pgmask:` refusal for its own.
  Remaining uniform expression, summary, rescue, star-expansion, and
  non-table-relation matrices use the same per-query isolation, including
  value checks on JSON extracts. Binary Bind of a document extract is covered
  alongside binary text extracts.
- Pin the JSON pointer trie and catalog overlap helpers with named lookup
  tables: exact beats `*`, object keys never take array wildcards, ambiguous
  text steps refuse at a `*` edge, nested wildcards need a proven array index
  at each `*`, and equal-specificity overlaps stay a load-time error.
- Add a property test that generates random accepted pointer sets and paths
  and cross-checks the compiled trie against a brute-force scan over the
  rule list. Any equivalence-preserving mutant on `compile`, `next_states`,
  `policy_at`, `has_ambiguous_wildcard`, or `has_descendants_at` diverges on
  some generated case; a temporary mutation was caught in seventeen cases
  before this landed. The generator keeps tables catalog load would accept
  by using the same equally-specific overlap predicate, then calls
  `validate_json_spec`. Rule segments include `0` and `*` so exact-index vs
  array-wildcard pairs appear; path `*` covers the literal object key.
- Add a live-Postgres JSON SQL value campaign. Sixty-six operator, function,
  cast/collation, alias/join/view/CTE/subquery, object, array, `json`/`jsonb`,
  unmatched-leaf, and whole-document queries first run directly against
  PostgreSQL, requiring poison values where applicable, then decode pgmask's
  raw-wire DataRows and compare the exact text, SQL NULL, or semantic JSON
  result; a five-field projection plus star expansion and a two-column view
  pin positional plan alignment. Forty-eight refused construction, expansion,
  JSONPath, dynamic/ambiguous path, mutation, aggregate, wrapper,
  and set-operation shapes likewise must expose a poison directly and produce
  pgmask's own refusal without one byte of poison. Binary Bind assertions now
  check the exact partial text mask and versioned masked jsonb document, not
  only absence of a canary. Pin the intentional disclosure from
  `json_unmatched = "none"` while proving a narrower pointer still wins, and
  apply byte/depth refusal checks to document extracts as well as whole
  columns. Fold the earlier canary-only JSON extract, constructor, and
  provenance matrices into these campaigns so a served shape has one exact
  value pin and a refused shape has one poison control. JSONB subscripting of
  exact object paths is attributed through the same parser; subscripts that
  could enter an array wildcard, plus negative, computed, sliced, or casted
  keys, stay opaque.

## 0.1.98 — Close then Bind of the same portal name does not inherit the rebound plan

- **`Close` must not reset bind generation while an Execute of that name
  is still in flight.** `PlanState::close` dropped
  `portal_bind_generations`. A later `Bind` of the same portal name
  started at generation `1` again and collided with the unfinished
  `PendingExecute` (also `1`). In one Sync, Execute runs before Describe
  is answered, so `pending.plan` is still `None`. `streaming_plan` then
  treated the rebound all-passthrough plan as current, and same-arity
  classified DataRows took `Vetted::unmasked_row` — email, name, and the
  rest of the poison row. No second Execute required. Unnamed portal
  `""`, `Close S` of the classified statement (implicitly closes its
  portals), and binary Bind of the classified Execute leaked the same
  way. Without Close the second Bind bumps to `2` and the proxy refuses
  (0.1.97). Two different portal names still serve.
- Fail-closed: bind generation is how many times the *name* has been
  Bound, not a Close-able resource. A Bind never reuses a generation an
  unfinished `PendingExecute` still holds. Unknown (no snapshot,
  generation no longer current) refuses DataRows rather than unmasking.
  Class-then-pass without Close stays fail-closed.
- **Defense-in-depth: ErrorResponse field `s` (SCHEMA) is now scrubbed.**
  `LEAKY_FIELDS` was `DHncdtqW` and omitted it. `RAISE … USING SCHEMA =
  email` puts the address in `s` — measured on a direct connection.
  `DO` / `CALL` / `CREATE FUNCTION` are frontend-refused, so `scrub_error`
  never sees that channel today. Kept dropped anyway so opening those
  gates cannot start forwarding it. Not a live disclosure.

## 0.1.97 — a different portal after PortalSuspended does not inherit the stale plan

- **`PortalSuspended` is not completion, and Postgres will run another portal.**
  After `Execute p_pass` with `max_rows=1` (`ship_city, id` — all passthrough),
  `pending_executes` still named `p_pass`. The next `Execute` of a *different*
  named portal (`email, name`, same arity) produced DataRows that
  `streaming_plan` judged with that leftover plan. An all-passthrough plan
  takes `Vetted::unmasked_row` and released the classified values in the
  clear — email, salary, birth, uuid, phone, IP, notes, address. A mixed
  plan leaked only the passthrough slots. Binary Bind and a same-Sync
  pipeline leaked the same way.
- The comment that PostgreSQL refuses a second portal while one is
  suspended was wrong; we measured it. `CommandComplete` then popped the
  *suspended* owner, so the rows were never bound to the portal that
  produced them. A resume of the *same* portal still shares one owner.
  Simple Query after suspend, unnamed-portal reuse, and `max_rows=0` then
  classified were already safe.
- Fail-closed: `suspend_result` drops the paused owner when a different
  portal is already queued or is Executed next, so `streaming_plan` is that
  portal's plan — or `None`, which refuses the DataRows. Over-refusal of
  that rare interleaving would also have been acceptable; leaking is not.
- **A failed resume after Sync is not a live owner.** Sync without `BEGIN`
  ends the implicit transaction; Postgres destroys named portal A
  (`SQLSTATE 34000`). Resume cleared `suspended` but left A on
  `pending_executes`. `discard_failed_epoch` returned early — no pending
  Parse/Bind/Describe — so Execute of `email, name` (same arity) queued
  behind the zombie and `Vetted::unmasked_row` released the values. Ghost
  Execute or Close+Execute then B already refused in some paths; A-then-B
  with no failed resume, and resume inside `BEGIN`, were already safe.
  Fail-closed: an ErrorResponse that completes an Execute discards that
  owner, and `streaming_plan` does not keep pointing at a portal that no
  longer exists.
- **A later-epoch error after suspend+Idle is not a live owner.** The
  resume-only epoch stamp closed only 34000 on A's own Execute. Any
  later-epoch ErrorResponse that is not that Execute — simple Query
  `SELECT 1/0` (H10a, 22012), Describe of the dead portal (H5b, 34000
  on Describe), Parse `SELECT !!!` (42601), Bind of a missing statement
  (26000), binary Bind of B after 1/0, a mixed plan's passthrough slot —
  left A's all-passthrough plan on `pending_executes`. Execute B queued
  behind it; same-arity classified DataRows took `Vetted::unmasked_row`.
  Postgres destroys named portals of an implicit transaction at
  transaction end: after `PortalSuspended`, `ReadyForQuery Idle` discards
  the suspended owner. `ReadyForQuery InTxn` does not (`BEGIN; suspend;
  Sync` keeps the portal). `discard_failed_epoch` also drops older-epoch
  Executes while `suspended`, so a pipelined error before that Idle
  cannot leave the zombie either. A-then-B with no intervening error,
  and the 34000-resume path, stay closed.
- **Rebinding the same portal before CommandComplete is not a resume.**
  Pipelining two full Executes (`max_rows=0`) that reuse one portal name
  let the second Bind overwrite `portal_plans` before the first DataRows
  were judged. `execute` treated the second Execute as a resume (the
  front already named that portal), so `streaming_plan` applied the new
  all-passthrough plan to the classified first result.
  `Vetted::unmasked_row` released the poison row — email, name, and the
  rest of the same-arity classified fields. Unnamed portal `""` (the
  JDBC/psycopg reuse pattern) and binary Bind leaked the same way.
  Pass-then-class over-masked (fail-closed). Two different portal names
  in one Sync, and a Sync between the two PBEs, were already safe. This
  is a sibling of the PortalSuspended owner-queue leak, without a
  suspend. Fail-closed: each Execute snapshots its plan onto the owner
  slot, Bind bumps a per-portal generation so a later Execute of the
  same name is a new result set, and unknown refuses DataRows rather
  than unmasking.

## 0.1.96 — Guard 7 follows FROM/CTE aliases to the real expression

- **A `ColumnRef` is not always a stored column.** Guard 7 judged closedness
  from the outermost target list, so
  `SELECT x FROM (SELECT city || (SELECT renamed_email) AS x)` looked like a
  closed column while `sqllineage` still reported only `city`. A FROM alias
  list (`AS t(id, a, …)`) hid the masked name from Guard 6. The same wrap
  leaked `name` and `phone` through the shipped GUI catalog (`lineage =
  "allow"`). Guard 7 now follows a subquery or CTE alias to the inner
  expression; a `SubLink` underneath stays unresolved. `SELECT upper(x)
  FROM (SELECT city AS x …)` still releases. Default posture was already
  refusing these (no provenance).
- **A FROM colnames list remaps attnums by position.** Independent of the
  wrap above: `SELECT upper(city) FROM customers AS t(id, city, …)` binds
  the released name `city` to email. Guard 6 never sees the word `email`;
  sqllineage reports `customers.city`. Guard 7 now treats a `RangeVar`
  with colnames as incomplete, the same inversion as `RangeFunction` and
  join-with-colnames. `SELECT upper(city) FROM customers` (no list) still
  releases. Default posture was already refusing (no provenance); hostile
  already refuses these lists.

## 0.1.95 — lineage Release is an allowlist; unicode-escaped names are decoded

- **A non-empty source list is not a complete source list.** `sqllineage`
  does not descend into a scalar subquery, so `city || (SELECT email FROM …)`
  reports only `city` and used to `Release` whenever that column was
  passthrough. Guard 7 inverts the question the way analysis does: the
  output expression must be a closed composition of columns and literals.
  A `SubLink`, a window, or a node kind we have not listed stays unresolved,
  even when every *reported* source is released. FROM-clause subqueries,
  CTEs, and a subquery in WHERE still resolve — they are not sources of the
  projected value. The unicode-escaped concat that leaked through the GUI
  catalog is now refused on the construct, not only on the name.
- **`lineage = "allow"` no longer releases a masked column spelled `u&"…"`.**
  Guard 6 asks whether a masked name appears anywhere in the statement. The
  token `u&"email"` is not the word `email`, so concatenating a released
  column with a unicode-escaped masked column inside a scalar subquery —
  `city || (SELECT u&"email" FROM …)` — returned the address in the clear
  through the shipped GUI catalog. The same hole held for hex escapes
  (`u&"e\006dail"`), `CONCAT`, and `ARRAY`. The lexer now decodes unicode
  identifiers (and fails the whole scan on `UESCAPE` or truncated hex); the
  lineage backstop unions those names with the parse tree, which already
  expanded the escapes on `ColumnRef`. Hostile counting stays on the lexer
  so a unicode ident is still one mention, not two. Bare `SELECT u&"email"`
  was already masked (OID provenance) and is unchanged.

## 0.1.94 — nullability-aware fallbacks; plan decisions extracted; row path fused

- **Automatic fallbacks preserve declared nullability.** A type-aware default
  no longer sends `NULL` for a catalog-resolved `NOT NULL` source column,
  including constraints inherited through nested domains. If the type has only
  a `NULL` mask, pgmask refuses the result before its row description; if a
  non-NULL mask fails for one value, it fails closed instead of degrading that
  value to `NULL`. This source-based check can conservatively over-reject an
  outer-join result. Explicit `unclassified_mask = "null"` keeps its
  operator-chosen behavior. Per-value leniency (below, 0.1.93) is accordingly
  limited to nullable or catalog-unresolved sources.
- **Plan decisions extracted from the session state machine.** `policy.rs` now
  owns "what plan does a described result set get"; `session.rs` keeps the
  wire I/O loop. Pure move, no behavior change.
- **The row masking path is one fused pass.** Each field is decoded, masked,
  and encoded straight into the outbound frame; the two intermediate
  per-row `Vec`s and the full extra copy are gone, and the pseudonym domain
  is absorbed into the HMAC state once per plan instead of once per value.
  A property test pins the incremental frame reader to `parse_data_row`
  byte-for-byte, and a unit test pins primed digests to unprimed ones.
- **One mask capability table.** `classify`'s `mask_fits` now maps
  information_schema type names to OIDs and delegates to `MaskSpec::supports`,
  failing closed on unknown types in both directions; a 224-pair agreement
  test pins the two together. The old string table accepted `numeric-bucket`
  on `money` (the proxy refuses it at runtime) and refused text masks on
  `name` (the proxy accepts them). Dead `Catalog::name_of` removed.

## 0.1.93 — type-aware defaults hardened: no mid-stream rejections, strict-null opt-out

Fixes from a review of the 0.1.92 type-aware defaults:

- **Fallback masks never kill a stream.** The old unclassified default
  (`NULL`) was total; the type-aware masks can fail per value. A fallback mask
  that cannot honour a value or format — an `infinity` timestamp, output under
  a non-ISO `DateStyle`, an inet column a Bind flipped to binary format — now
  nulls that field instead of rejecting the result set mid-stream.
  Operator-configured masks stay fail-closed.
- **`unclassified_mask` is back, as a policy choice.** `type-aware` (default)
  or `null`, which restores the strict pre-0.1.92 posture of `NULL` for every
  unclassified value. A config still carrying the removed knob's
  `unclassified_mask = "null"` keeps its old strict meaning instead of failing
  to boot; the old universal-mask values (`redact`, `none`, …) stay rejected.
- **Pseudonym domains only from stable identities.** The fallback no longer
  keys a pseudonym domain on the volatile relation OID plus the client-chosen
  output alias. A column the catalog has not resolved yet nulls instead —
  an unstable "stable handle" breaks the joins it exists to preserve.
- **Email-shaped pseudonyms honour domain separation end to end.** The
  employer half of a pseudonymised email was keyed only on the plaintext
  domain, so columns in different pseudonym domains emitted linkable `@…`
  halves. It now mixes in `spec.domain` like the value half. Emitted
  email-shaped pseudonyms change under the same key.
- **Declared column widths are respected.** A pseudonym no longer overflows a
  narrow `char(n)`/`varchar(n)`; columns too narrow to hold every pseudonym
  shape fall back to `NULL`.
- **`classified_column_names` means classified again.** The all-columns name
  map added for pseudonym domains is now a separate snapshot field, restoring
  the rejection-bucketing metric's meaning, the refresh change-detector's
  scope, and the refresh loop's cost.
- **One capability table.** `MaskSpec::for_unclassified` now selects from
  `MaskSpec::supports` instead of hand-copying its type arms.

## 0.1.92 — hostile SQL gate: agg ORDER BY, JSON_TABLE, PREPARE, SEARCH/CYCLE, JSON agg

### Type-aware defaults for unclassified columns

`unclassified = "mask"` now pseudonymises text and UUID values, reduces dates
and timestamps to a year, and removes host bits from text-format IP addresses.
Numeric, boolean, structured, custom, and unsupported binary values remain
withheld as `NULL`.

This removes the `unclassified_mask` setting. Delete that line before upgrading;
configs that still contain it are rejected at startup. Pseudonyms use stable,
column-scoped domains so unrelated unclassified columns are not linkable.

The lockfile also updates `h2` to 0.4.16, fixing RUSTSEC-2026-0258.

Live membership / cleartext-row oracles under `posture = "hostile"` that
`pg_query::nodes()` never visits. Unicode-escaped masked names
(`u&"email"`) are invisible to the lexer, so a missed node was an allow:

- Unknown `pg_stat_*` relations are leaky. The previous denylist named
  `pg_stat_activity` / `pg_stat_statements` / `pg_stat_wal_receiver` and
  treated the rest as metadata-only — the same polarity as target-list
  `FuncCall`. `SELECT query FROM pg_stat_monitor` (and `pg_qualstats.constvalue`,
  `pg_store_plans.plan`, the next extension) is other sessions' SQL with
  literals, including masked ones. Core counter / LSN / progress views
  (`pg_stat_user_tables`, `pg_stat_replication`, `pg_stat_ssl`,
  `pg_stat_progress_*`, `pg_stat_statements_info`, …) stay allowed so
  table-size dashboards and `\d` keep working. Listed `pg_statio_*`
  views (block I/O counts) stay allowed; an unseen name in those
  families is leaky. `pg_qualstats*` /
  `pg_store_plans*` join the refuse list by prefix (same class, different
  naming). Same class again, still not `pg_stat_*`: `pg_show_plans*`
  (running query text + plans) and `pg_query_state*` (other backends'
  current SQL) were catalog-shaped and metadata-only. Forks that install
  the dump in `pg_catalog` under another name (`citus_stat_activity`,
  `edb_stat_activity`, `citus_stat_statements`) fail closed on substring.
  `pg_wait_sampling_{profile,history,current}` (queryid + wait counts) and
  `pg_buffercache` (block IDs, not tuple bytes) stay allowed; an unseen
  `pg_wait_sampling_*` sibling is leaky. Citus still dumps in `pg_catalog`
  without those names: `citus_lock_waits` (blocked SQL), `citus_stat_tenants`
  (live distribution-column values), and `pg_dist_*` (`authinfo` passwords,
  `poolinfo`, background-task SQL, range-partition keys). Those prefixes
  are leaky; `\d` of a heap does not read them. The denylist polarity is
  now inverted for every catalog-shaped RangeVar: only classified-safe
  `pg_catalog` heaps/views (listed progress / `pg_statio_*` / counter
  `pg_stat_*`) and the SQL-standard information_schema name/grant views
  keep the fast path. An unseen `pg_stat_progress_*` is leaky until
  classified. `pg_catalog.hypopg_list_indexes` and
  `information_schema.not_a_real_view` are leaky; `\d` still reads
  `pg_class` / `pg_attribute` / `information_schema.tables`. Unqualified
  fork names without a `pg_` prefix (`citus_lock_waits`) stay on the
  substring rules. The vanilla PostgreSQL 18 surface is classified once
  (`catalog_surface.rs`): every official heap, system view,
  monitoring-stats view, and `information_schema` relation is
  metadata-safe XOR leaky. Classified-leaky names are leaky in any
  schema (`public.pg_stats`, unqualified `user_mapping_options`). CI
  fails on duplicates, unsorted names, or a `SELECT * FROM
  pg_catalog.{name}` that disagrees with the table. Unknown
  catalog-shaped names stay leaky. Named contrib exceptions
  (`pg_buffercache`, `pg_stat_statements_info`,
  `pg_wait_sampling_{profile,history,current}`) stay off the vanilla
  table. The leaky-catalog gate lives in that file. Fork substrings skip
  `pg_*` names, so `pg_stat_statements_info` is not a special case on
  `stat_statements`.
- SQL `PREPARE` / `EXECUTE` / `DEALLOCATE` and `DECLARE` / `FETCH` / `CLOSE`
  are now refused on **every posture** (`sql_prepare_cursor`). They are a
  second copy of Parse/Bind/Execute whose bodies `nodes()` does not enter.
  Analysts keep ordinary `SELECT` (including `SELECT … FETCH FIRST n ROWS`,
  a limit clause) and the extended protocol. Walkers on PREPARE/DECLARE
  bodies remain as defense in depth. `EXPLAIN SELECT email FROM t` is the
  same residual as the inner SELECT; `EXPLAIN` of a predicate oracle is not.
- `pg_cursors` (session cursor SQL text) and `pg_stat_wal_receiver` (conninfo)
  are refused as leaky catalogs, same class as `pg_prepared_statements` /
  `pg_subscription`. `pg_user` (passwd) joins `pg_shadow` / `pg_authid`.
- `CAST(1 AS numeric((SELECT count(*) WHERE u&"email" = 'x'), 0))` — TypeCast
  never entered `TypeName.typmods`, a subquery membership oracle. The shared
  walk now visits typmods (and ColumnDef / XMLSERIALIZE / JSON_TABLE column
  types), plus other previously skipped children (`JoinExpr.join_using_alias`,
  `ResTarget.indirection`, `VariableSetStmt.args`, `ExplainStmt.options`,
  `PrepareStmt.argtypes`, `ExecuteStmt.params`, `CopyStmt` query/WHERE).
  `JSON_VALUE` / `JSON_QUERY` `RETURNING numeric((SELECT …), 0)` is the same
  oracle on `JsonOutput.type_name`, which is not a TypeCast and not a Node.
- `SELECT database_to_xml(…) FROM pg_class` (and `schema_to_xml`,
  `pg_stat_get_activity()`, `pg_ls_logdir()`, logical-slot peek/get) looked
  like a metadata-only catalog query, which skips the untrusted-function
  gate. The escape list now covers the rest of the `*_to_xml` family and
  those target-list dumps. Same polarity, later pass: `pg_stat_get_wal_receiver()`
  (conninfo), `crosstab` / `connectby` (SQL-as-string), the rest of `dblink_*`,
  adminpack `pg_file_read` / `pg_logdir_ls`, `loread` / `lo_open`, and
  `pg_walinspect` record dumps. Target-list `FuncCall` is now an allowlist
  (helpers / trusted names / FROM-generators); a denylist of dump names was
  an allow for every unnamed one (`get_raw_page`, `pg_sleep`, `set_config`,
  `pg_file_write`). The escape list remains defense in depth. `format_type` /
  `pg_get_viewdef` stay helpers, not dumps.
- TOAST heaps (`pg_toast.pg_toast_<oid>` / unqualified `pg_toast_*` after
  `SET search_path TO pg_toast`) hold toasted bytes of user columns. They
  were catalog-shaped (`pg_` prefix) and not on the leaky-name list, so
  `SELECT count(*) FROM pg_toast_NNNN WHERE chunk_data LIKE '%x%'` was a
  membership oracle the snapshot never names. `pg_foreign_server` /
  `pg_foreign_data_wrapper` options join user mappings (connection secrets).
  `pg_foreign_table` stays off the list so `\d` of a foreign table still
  works. `pg_roles` is still allowed (`\du`).
  SQL-standard wrappers of the same option catalogs
  (`information_schema.user_mapping_options` /
  `foreign_server_options` / `foreign_data_wrapper_options`) were
  metadata-only because they live in `information_schema` and never name
  `pg_user_mapping`. The other two PUBLIC option views
  (`column_options` / `foreign_table_options`) and the internal
  `_pg_user_mappings` / `_pg_foreign_*` base views (raw `umoptions` /
  `srvoptions` / `fdwoptions` / `ftoptions` / `attfdwoptions`) were the
  same hole. `information_schema.user_mappings` / `foreign_servers` /
  `foreign_tables` / `foreign_data_wrappers` (names, no option values)
  and `information_schema.tables` stay allowed.
- Hostile / read-only / write gates share one descent (`walk_tree` /
  `for_each_child_node`) and one cached parse (`StatementInspection`) instead
  of a parallel `tally_*` match plus `pg_query::nodes()`. The parser is still
  pg_query; `nodes()` is not a complete visitor (upstream: it skips node
  types, including LIMIT and window frames), so absence proofs — masked
  names, writes, leaky catalogs, metadata-only, provenance, qualification —
  use the local walk. The session frontend gates parse once. `EXPLAIN INSERT`
  is a write because the inner statement is visible on that walk.
- `string_agg(city, ',' ORDER BY u&"email" = 'x')` / `WITHIN GROUP (ORDER BY …)`
  — `FuncCall.agg_order` was never walked
- `ROWS BETWEEN (SELECT … WHERE u&"email" = 'x') PRECEDING AND CURRENT ROW`
  — `WindowDef.start_offset` / `end_offset` skipped
- `JSON_VALUE` / `JSON_QUERY` / `JSON_EXISTS` / `JSON_TABLE` around those names
- `PREPARE q AS SELECT count(*) WHERE u&"email" = 'x'` then `EXECUTE q` —
  `nodes()` does not enter `PrepareStmt` / `DeclareCursorStmt` query bodies
- Whole-row `t::text` inside `ARRAY[]`, `JSON_OBJECT`/`JSON_ARRAY`,
  `xmlserialize`, `LIMIT (SELECT … t2::text …)`, aggregate `ORDER BY t::text`,
  and window `PARTITION BY` / `ORDER BY t::text` — binders inside `LIMIT` were
  also invisible to `nodes()`, so the inner alias was never a row variable
- `WITH RECURSIVE r AS (SELECT * FROM …) SEARCH DEPTH FIRST BY u&"email"` —
  `CommonTableExpr.search_clause` / `cycle_clause` were never walked, and
  `SELECT *` names no column for the projection tally to notice
- `json_arrayagg(t)` / `json_objectagg('k': t)` / `JSON_SERIALIZE(t)` /
  `t IS JSON` — JSON aggregate / serialize / IS JSON nodes were tallied for
  unicode names but skipped by the whole-row child walk
- `XMLTABLE (… COLUMNS … DEFAULT u&"email")` — `RangeTableFuncCol.coldefexpr`
- `PREPARE` of `NATURAL JOIN` / `FROM t AS x(c1,c2,…)` — join/rename walked
  `nodes()`, which does not enter PREPARE/DECLARE bodies
- `(SELECT * FROM customers) AS t(c1,c2,…)` and `WITH q(c1,c2,…) AS (SELECT *)`
  — column-list aliases on subqueries and CTEs hid `email` behind `c2`
- `json_arrayagg(city) OVER (PARTITION BY u&"email")` — `JsonAggConstructor.over`
- `analysis.rs` is now `crates/proxy/src/analysis/` (`walk`, `names`, `safety`,
  `catalogs`, `hostile`, `frontend`). Public `crate::analysis::*` paths are
  unchanged.

Unparseable SQL with a unicode-escaped masked name failed *open*: the lexer
sees no `email` token, the tree walk returns nothing, and the gate treated
"no counts" as safe. It now refuses when the statement does not parse.

Fixed by walking those node kinds in the projection tally, collecting row
binders and whole-row refs from the statement root (not `nodes()`), walking
join/rename the same way, and failing closed on a parse error whenever the
catalog has masked names.

### Reducing aggregates over masked columns are masked, not exact

The last unmasked output found in the field. Everything else on every channel —
simple and extended protocol, text and binary, error messages, notices — was
already masked or refused; the one thing that returned data in the clear was a
reducing aggregate over a masked column, exactly as the module header had
recorded it as accepted.

`sum`/`avg`/`stddev`/variance/regression aggregates are useful precisely because
they collapse a set, and a set an attacker collapses to one row collapses to the
value:

    SELECT sum(annual_salary) FROM people WHERE id = 1        -- exact salary
    SELECT sum(annual_salary) FROM people WHERE id IN (1, 2)  -- two salaries
    SELECT sum(annual_salary) FILTER (WHERE id = 1) FROM t
    SELECT sum(annual_salary) FROM (SELECT … WHERE id = 1) t
    … and the same through CTEs, in binary results, and over `email`/`birth_date`
    columns that are column-wise unique but not declared keys.

That last class is what made it undecidable: whether a predicate matches one row
is a property of the data, not of the statement, and `WHERE birth_date = '…'`
cannot be refused the way `GROUP BY id` could. The unique-key `GROUP BY` guard
(the 0.1.16 disclosure) already refused the decidable subset.

Closed by giving the precision up instead of the summary. A reducing aggregate
now resolves its source (`Safety::Summary`): over a *released* column the exact
summary is served; over a *masked* column the output is masked with that
column's own mask, so a sum over a bucketed column is a bucket
whatever the predicate collapses it to —

    SELECT sum(annual_salary) FROM people               -- was 54000250710
                                                        -- now 54000250000
    SELECT sum(annual_salary) FROM people WHERE id = 1  -- now 900000000

Summary masking now has one source-selection path whether lineage is enabled or
not. For the shape every disclosure used — one bare aggregate argument over
explicitly schema-qualified named FROM ranges — the session attributes the
column from the statement and catalog directly. Requiring the schema is
load-bearing: defaulting an unqualified name to `public` can select a weaker mask
than the relation PostgreSQL resolves through `search_path`. Expression
arguments, joins, subqueries, unqualified ranges and multi-argument regressions
fall to the opaque posture; lineage can still release them only when every
source is explicitly released. A blocked lineage source is diagnostic and can
no longer choose an output mask by itself.

`count`, `count(*)` and `regr_count` stay passthrough. Boolean aggregates are
summaries: over a singleton set `bool_or(x)`, `bool_and(x)` and `every(x)` are
exactly `x`, so a masked boolean must mask their output too.
Aggregates that return a stored value (`min`, `max`, `string_agg`, …) were
already refused and still are. `summaries = "refuse"`, the `lineage`/`opaque`
postures and the unique-key GROUP BY guard all keep their existing force; the
change sits entirely inside the summaries relaxation.

Type-incompatible mask applications fail closed: `sum(… )::text` over a
bucketed column, and `avg` (numeric) in binary results, are refused with a
`mask_type_mismatch` rather than guessed at — the same rule the projection
masks have always used.

## 0.1.91 — hostile SQL gate: JOIN ON, BooleanTest, JSON, xmlserialize

Four live membership oracles under `posture = "hostile"` that returned
exact-match counts on unicode-escaped masked columns:

- `JOIN … ON u&"email" = '…'` — `JoinExpr.quals` was never walked
- `(u&"email" = '…') IS TRUE` — `BooleanTest` skipped in the tallier
- `JSON_OBJECT('e': u&"email")` / `JSON_ARRAY(u&"email")` — JSON constructor nodes
- `xmlserialize(CONTENT xmlforest(u&"email" AS e) AS text) LIKE …`

Fixed by walking `from_clause` / join quals and extending
`tally_masked_column_refs_in` for BooleanTest, XmlSerialize, NullIfExpr,
ScalarArrayOpExpr, and the JSON constructor / aggregate / predicate family.

## 0.1.90 — adversarial hardening of the masking path (six findings)

Found by attacking a running proxy with a raw wire client, in an adversarial
session that set out to unmask data and could not.

A client that pipelines `Parse, Describe(Statement), Bind, Execute` in one
flush — sending all four before reading anything — got:

    ERROR: pgmask: value of type OID 1082 did not decode in text format

when it asked for binary results. Two round trips worked. Postgres served both.

Three things had to line up. `bind` runs while the backend's RowDescription is
still in flight, so there is no statement plan to stamp and the Bind's format
codes were dropped. `execute` then finds no portal plan. And
`finish_description` sets the active plan to the *statement's*, whose formats
are text — all a statement-level Describe can report, since formats are not
chosen until Bind. The binary rows then failed to decode.

The re-stamp for this case already existed and carried a comment describing it
exactly. Only the pipelined arrival order was missed, and that order is what
performance-minded drivers use — pgjdbc's binary transfer and libpq pipeline
mode both qualify.

Fixed by remembering each portal's Bind formats and applying them at
BindComplete, which the measured message order puts after the RowDescription
and before the first DataRow: ParseComplete, ParameterDescription,
RowDescription, BindComplete, DataRow.

NOT A LEAK, AND THE REASON MATTERS

It failed closed, and text-family types were never affected because their text
and binary encodings are identical — verified, not assumed: pipelined binary on
`email` and `name` returned the pseudonym and `***` both before and after.

It still deserved fixing at this weight. A proxy that refuses legitimate
queries is one an operator routes around, which is the same argument the TLS
startup bug made.

WHAT ELSE THE SESSION TRIED

Around forty queries in eight classes, none of which unmasked anything:
whole-row and composite escapes (`SELECT c FROM t c`, `row_to_json`, `(c).email`,
`ROW(email)`); aliasing a masked column to a released column's name; CTAS, temp
tables, attacker-defined views and functions, `RETURNING`, `COPY TO STDOUT` —
all dead because pgmask is read-only on every posture; SQL-as-a-string
(`table_to_xml`, `query_to_xml`, `xpath` over it, `schema_to_xml`) and superuser
`pg_read_file`, all refused as opaque; provenance confusion via `UNION ALL`,
`COALESCE`, `CASE`, scalar subqueries, LATERAL, window functions, CTE
reordering and recursive CTEs; and the binary-format matrix above, including
mixed per-column format codes in both orders.

Four regression tests, each failing without the fix — including one that pins
the fail-closed path the fix must not open: executing a portal that was never
bound still has no plan.

### The plan cache is safe; the column-rename trap is not, and --check now catches it

Closed the last catalog-race question: can a cached extended-protocol plan
outlive a refresh and mask the wrong data? No. A raw wire client that Parses,
Describes, Binds and Executes, then reshapes the table from another connection
and re-Executes, is refused both ways — invalidate_if_stale clears the plans on
the generation bump, and the SELECT * reorder is caught by the backend's own
result-type check. Nothing served.

But going deeper found one more real exposure — name-based masking defeated by a
column rename. RENAME ssn <-> city leaves the rule "release city" pointing at
the SSN column, and a plain SELECT city returns it in the clear, under
default-deny. It needs DDL (a rename) from a privileged source, so a read-only
client cannot cause it — but a read-only SELECT then exposes it. It is inherent
to name-based classification.

The fixable part is detection. classify --check was structural — it compares
rules to schema shape, which a rename leaves intact — and classify's generate
mode name-matches first and skips content sampling, so both missed it.
`--check --sample N` now samples the columns the catalog releases and fails if
their values look sensitive (verified: flags a released column that is 100%
SSN-shaped, does not flag one holding real city names). Without --sample,
--check now says it did not look at values rather than implying it did.

### And a catalog-race window under allow (with a fix)

Hammering the catalog-refresh path turned up a real leak — the first read-side
one this red-team found. Under `unclassified = "allow"`, an
`ALTER TABLE ... DROP COLUMN x; ADD COLUMN x` moves `x` to a new attnum while
keeping the table OID. The snapshot misses on the new attnum, and under `allow`
a miss releases, so an explicitly-masked column was served in plaintext — and
because a known table OID nudged no refresh, for the *entire* refresh interval:
measured at 30s, every query in a 200-query poll leaking.

Fixed by nudging a refresh on any lookup miss, not only unknown relations,
which bounds the window to `catalog_refresh_min_seconds` (5s default, measured
1s at floor 1s). The residual is inherent to `allow` + async refresh: a
reshaped column is indistinguishable from a genuinely new one, which `allow`
releases by design.

Default-deny was and is safe — a miss masks with no timing dependence — and
`a_reshaped_masked_column_stays_masked_under_default_deny` pins it (poisoned:
forcing release-on-miss fails it with the canary crossing). 45s of DDL churn
against a query storm under default-deny leaked nothing.

### Deployment guidance: point it at a read-only upstream

The write-side hardening — parser-based write refusal, and any backend
`default_transaction_read_only` flag — is defense in depth for one
configuration: pgmask in front of a writable primary with a privileged role.
Verified against a live backend that a read-only *upstream* moots it entirely:
as a `SELECT`-only role, the escape that defeats a per-session read-only GUC
(`SET default_transaction_read_only = off; INSERT`) is refused by privilege
alone, before pgmask's parser is consulted. A hot standby is stronger still —
writes are physically impossible with no GUC to flip.

A prototype backend-read-only injection was built and then dropped: on its own
it is a per-session GUC the client can switch off, so shipping it as a
"read-only" guarantee would be the false-assurance pattern this document keeps
cataloguing. The honest guard is a read-only role or replica, now documented as
the strongest of the three write layers. None of this touches the masking
surface, which is where every real disclosure lives.

### And a multi-statement test that could not see a leak

A third adversarial pass. Still no way to read a masked value — role
relaxations do not escalate through `SET ROLE` or `SET SESSION AUTHORIZATION`
(keyed on the startup user, which those do not change), portal suspension and
resume mask every page, describing one portal while executing another uses the
executed portal's plan, and rebinding a portal name is refused.

But `multi_statement_simple_query_stays_masked` was another vacuous test. It
sent three result sets in one `Query` and asserted only that no canary crossed
— which a *refusal* satisfies exactly as well as correct masking, because an
error carries no canary. And a refusal is what happens: pgmask cannot pair the
Nth RowDescription with the Nth statement, so
`analysis::provenance_is_trustworthy` returns false for any multi-statement
parse and every field is treated as opaque. The test passed whether each set
was masked by its own plan, nulled, or the whole query rejected — so it could
not have caught the very mispairing its comment describes, a second set served
under the first statement's plaintext plan.

Rewritten to pin the real behaviour: fail-closed, and specifically not that
leak. Poisoned by pointing it at a served single statement, which now fails
with "a served result set here is a mispairing that must be proven masked."

The behaviour itself — every multi-statement simple query refused, including
`SET search_path = x; SELECT ...` — is now documented as the compatibility
limitation it is, verified fail-closed in both the `reject` and `mask`
postures.

### And `--check` called plaintext a coverage gap

A second adversarial pass, this time against objects an attacker would find in
a real database rather than SQL they could write. Still no way to unmask a
value under the default posture — views, materialised views, inherited children
and partitions over a classified table all came back NULL, with rows returned
1/1 so it is masking and not an empty result. But:

**Under `unclassified = "allow"` an undeclared view over a classified table
serves plaintext.** `SELECT email FROM demo.v_plain` returned
`user1@example.com`. So did a view that renames the columns, so the column
*named* `city` returned the address.

That much is documented — README says views need their own entries, `classify`
does propose them, and `allow` releases what is undeclared. The defect is what
the drift gate says about it:

    19 column(s) have no rule. Default-deny masks them, so this is a
    coverage gap and not an exposure

printed unconditionally, against a catalog that sets `unclassified = "allow"`,
by a function holding that parsed catalog in a local called `config`. The one
setting that decides whether those columns are an exposure was never consulted.
`--check` is the command operators are told to run in CI, so this is a green
build asserting safety about columns being served in the clear.

It now reads the setting. Under `allow` it names them as SERVED IN PLAINTEXT
and fails with a reason; under default-deny the wording is unchanged except to
say which posture it is describing.

TWO OF THE THREE TESTS I WROTE FOR THIS COULD NOT FAIL

Worth more than the fix. The first refuted the string `"not an exposure"` —
which never appears, because that wording wraps across a newline. The second
asserted a non-zero exit, which a coverage gap already produced in both
postures. Both passed no matter what the code did; the poison run failed 1 of 3
and that is how they were found. All three discriminate now: 23/0 clean, 3
failures with the fix stubbed out.

And the first version of the harness had the postures backwards — it built an
"allow" catalog from a file that was already `allow`, because this suite writes
that setting itself so its "unclassified column arrives intact" test can work.
Both halves then described the same posture.

## 0.1.89 — hostile closes ARRAY/CASE/LIMIT/indirection unicode oracles

Unicode-escaped masked names still slipped through inside node kinds the tally
did not descend into:

- `ARRAY[u&"email"]` / `(ARRAY[…])[1]` / `ANY(ARRAY[…])`
- `CASE u&"email" WHEN …`
- `LIMIT` / `OFFSET` scalar subqueries with masked predicates
- `(t).u&"email"` (`A_Indirection`)
- `FILTER (WHERE … ARRAY[u&"email"] …)`
- `xmlforest(u&"email")` / other `XmlExpr` named args (`ResTarget` wrappers)

Hostile now walks each `SelectStmt`'s clauses comprehensively (including
`WHERE`/`LIMIT`/`OFFSET` and the new expression node kinds) so decoded names
inside those containers are counted once against the projection gate.

## 0.1.88 — hostile closes NATURAL JOIN, column-alias rename, unicode USING/PARTITION

Further membership oracles that never named a masked column in a tallied place:

1. **`FROM t AS x(c1,c2,…)`** renames `email`→`c2`, then `WHERE c2 = '…'` /
   `LIKE` recovers cleartext membership.
2. **`NATURAL JOIN`** (including `NATURAL JOIN (VALUES (…)) v(u&"email")`)
   equates on masked columns without naming them in predicates.
3. **`USING (u&"email")`**, **`PARTITION BY u&"email" = …`**, **`GROUP BY
   GROUPING SETS / ROLLUP / CUBE (u&"email")`**, and CTE `aliascolnames` with
   unicode-escaped masked names — decoded `String` / `WindowDef` / `GroupingSet`
   nodes the previous tally missed.

Hostile now refuses column-alias lists on relations that have masked columns,
refuses NATURAL JOIN when a side carries masked columns, and extends the
ColumnRef/name tally into `USING`, window `PARTITION BY`/`OVER`, `DISTINCT ON`,
`GROUP BY` (including grouping sets), CTE colnames, and `Alias.colnames`.

## 0.1.87 — hostile closes unicode-identifier and ORDER BY predicate oracles

Two bypasses of the hostile masked-column gate:

1. **Unicode-escaped identifiers** (`u&"email"`, `u&"e\006dail"`) never appear as
   the bare word `email` in the token stream, so the lexical count missed them
   while Postgres still evaluated the cleartext column. Hostile now also counts
   decoded `ColumnRef` names from the parse tree (max with the lexical count).
2. **`ORDER BY email = '…'`** was credited as an accepted cleartext sort, but is
   a membership oracle. Only *simple* sort keys (`ORDER BY email`, optional
   cast/collate) are credited now.

## 0.1.86 — hostile closes whole-row cleartext oracles

`SELECT count(*) FROM customers t WHERE t::text LIKE '%secret%'` (and
`format('%s', t)`, `concat(t)`, `customers::text`, `JOIN … ON a::text = b::text`,
`count(*) FILTER (WHERE t::text …)`) never named a masked column, so the lexical
hostile gate allowed them. Postgres still embeds every column's cleartext in the
row text — a full membership oracle.

Hostile now refuses whole-row references to FROM items (`hostile_uses_whole_row`)
at the frontend, before Postgres runs — including aggregate `FILTER` and
`COLLATE` subtrees that `pg_query`'s node walk does not descend into, and row
aliases from `FROM (subquery) t` / `RangeFunction` / joined aliases.

## 0.1.85 — hostile accepts cleartext ORDER BY of masked values

Sorting by a masked column (`ORDER BY email`, `ORDER BY 1`, `SELECT * ORDER BY
n`) does not put cleartext on the wire — only the row order of already-masked
cells. That is an accepted trade for exploration; 0.1.83 / 0.1.84 refused it.

Hostile still refuses predicates and other *value* inference
(`WHERE`/`LIKE`, single-row aggregates, error-channel `CASE`). `ORDER BY`
mentions of masked names are credited in the projection gate so
`SELECT id … ORDER BY email` works again.

## 0.1.84 — hostile closes SELECT * ORDER BY n

`SELECT * FROM customers ORDER BY 2` (when column 2 is `email`) still sorted by
cleartext after 0.1.83: the star made ordinals unresolvable, and the fail-closed
path only triggered when a *bare* masked column was projected. Hostile treated
an unreadable sort/group key under `SELECT *` as masked whenever the FROM
clause named a relation that has masked columns. Superseded by 0.1.85 (accepted
cleartext sort order).

## 0.1.83 — hostile closes ORDER BY 1 / alias cleartext-order oracles

`SELECT email FROM t ORDER BY 1` (and `ORDER BY alias` / `GROUP BY 1` /
`DISTINCT ON (1)`) named the masked column only once, as a bare projection, so
the lexical hostile gate allowed it. Postgres still sorted by cleartext, then
the proxy masked — returning pseudonyms in cleartext order.

Hostile resolved sort/group/distinct keys (including ordinals and output
aliases) and refused when any key was a masked column. Superseded by 0.1.85.

## 0.1.82 — hostile + leaky catalogs refused before Postgres

Two execute-then-refuse gaps remained after the projection and write gates:

1. **Hostile predicates still ran on the backend.** The masked-column rule lived
   only on `RowDescription`, so `WHERE email = …` / error-channel `CASE` still
   executed (timing and error-presence) before the client saw a refusal. The
   same rule now runs in the frontend gate, before the statement is forwarded.
2. **Leaky system catalogs** (`pg_stats`, `pg_statistic`, `pg_stat_activity`,
   `pg_authid`, …) were nulled rather than refused. Cleartext MCV cells did not
   return, but the query still ran. They are now refused at the frontend on
   every posture (`leaky_catalog`).

## 0.1.81 — hostile closes WHERE on unclassified columns

Default-deny nulls unclassified columns in the projection (`internal_note` in
the demo, and every column of an uncatalogued table). Under
`posture = "hostile"` those names were still usable in `WHERE` / `LIKE` /
error-channel `CASE`, so `WHERE internal_note = 'secret'` or
`WHERE token = '…'` recovered the cleartext the SELECT list had nulled.

Hostile's masked-name set now includes unclassified columns from the schema
snapshot. Bare names that are passthrough (`mask = "none"`) on any catalogued
column stay usable as filters (`WHERE id = 1`, `WHERE city = …`).

## 0.1.80 — fail-closed read-only allowlist

The write gate was a denylist of statement nodes. `CREATE VIEW` was missing:
under hostile read-only a client could still `CREATE VIEW demo.v AS SELECT email
…` and the backend stored a cleartext definition (direct DB access then saw
emails; the proxy continued to mask `SELECT` from that view). `LOAD` and
`CHECKPOINT` slipped through the same hole.

`is_write_statement` is now an allowlist of read/session statement classes
(`SELECT` without row locks / `INTO`, `EXPLAIN`, `SET`/`SHOW`, transactions,
prepare/execute, cursors, `DISCARD`). Every other `*Stmt` is refused
(`write_refused`) before Postgres runs it.

## 0.1.79 — refuse untrusted functions and FOR UPDATE

Preinstalled `SELECT demo.sleep_if(…)` still ran under read-only + hostile: the
result was opaque-refused, but timing recovered email prefixes. Any `FuncCall`
outside a trusted `pg_catalog` allowlist is now refused at the frontend
(`untrusted_function`), before Postgres executes it. Metadata-only catalog SQL
is exempt. `SELECT … FOR UPDATE` / `FOR SHARE` join the read-only write gate.

## 0.1.78 — read-only: refuse all writes

pgmask is a masking proxy for reading. Under every posture it now refuses DML,
DDL, `COPY`, data-modifying CTEs, `DO`, `CALL`, `NOTIFY`/`LISTEN`, and similar
mutating SQL at the frontend (metric `write_refused`) — before Postgres runs
them.

That closes the live exfil paths found under hostile: `INSERT … SELECT email`,
`UPDATE … WHERE email = …` rowcount oracles, and `CREATE TABLE` through the
proxy. `SELECT` of a preinstalled function can still *execute* for timing side
effects; its return value remains opaque-refused.

## 0.1.77 — hostile refuses DO / CALL / CREATE FUNCTION

Timing and exception-presence oracles under `posture = "hostile"` never needed
a projection: a `DO` block reads masked columns with `SELECT … INTO` and encodes
the answer as sleep or success-vs-error. Notice caps and rate limits only raise
the cost.

Hostile now refuses `DO`, `CALL`, and `CREATE FUNCTION`/`PROCEDURE` at the
frontend (metric `hostile_procedural`). Exploration stays on `SELECT`.

## 0.1.76 — cap notices per exchange

Rate limits charge one token per `Query`/`Execute`, so a single `DO` block can
still encode a full masked value as hundreds of NOTICE/INFO messages — measured:
full email recovery in one statement via run-length encoding.

`max_notices_per_exchange` (0 = off) drops excess `NoticeResponse` traffic until
the next `ReadyForQuery` and counts `notice_flood` once per crossing. Pair with
`posture = "hostile"` and `rate_limit_per_minute`.

## 0.1.75 — per-principal statement rate limits

The notice-channel oracle under `posture = "hostile"` recovers a full email in
a few hundred `DO` blocks: each is a simple query that never projects a masked
column, so the projection gate has nothing to refuse. Closing that without a
PL/pgSQL interpreter means making the campaign expensive.

`rate_limit_per_minute` / `rate_limit_burst` (off by default) charge every
authenticated `Query` and `Execute` against a shared per-username budget. Over
budget: SQLSTATE `54000`, metric `rate_limited`. Simple queries get a synthetic
`ReadyForQuery`; extended `Execute` waits for the client's `Sync`.
||||||| f2b04a4


## 0.1.74 — the skip counter had never counted a skip

`scripts/test-all.sh` has printed this on every run it has ever made:

    ok    cargo test    521 tests (0 need Postgres)

Forty-one of them were skipping. `skipping by request` is an `eprintln!` inside
a test that then *passes*, and libtest captures the output of passing tests, so
the line the counter greps for never reached the log.

The counter exists **because** those 41 tests once reported PASS while
asserting nothing. It was added to make that visible, and it reported zero from
the day it was written.

`--nocapture` on both sweeps makes the skips real — verified: 41 visible, and
319 + 202 = the 521 the summary already claimed. The count is now compared
against the number of tests carrying `require_pg!`, derived from the source, so
a mismatch fails the gate instead of printing quietly. The historical value, 0,
fails it.

Found sideways. A CI assertion failed reporting "sweep skipped 0, tests
carrying require_pg!: 41", and the first reading was that the assertion was
wrong. It was right about the discrepancy and wrong about which side was
broken.

Also: the comment above that code said 31 where the suites hold 41 — the same
stale number fixed in `support/mod.rs` two releases ago, in the other place it
had been copied to.

And the first cut of this fix broke a different drift check: it wrapped the
summary in an if/else with a `record` call in each branch, and
`check-repo-invariants.sh` derives the suite count by counting those, so it
reported 22 suites where the gate runs 21. One `record`, message chosen first.

There is no 0.1.72. It was written, then renumbered when a concurrent session
landed 0.1.73 first; leaving the gap is more honest than renumbering theirs.

## 0.1.73 — hostile posture, and verify-full on the backend leg

Two of the holes the poison run measured, closed with the smallest knobs that
do it.

`posture = "hostile"` forces `summaries = "refuse"` and refuses any statement
where a masked column appears more often than as a bare outermost SELECT-list
`ColumnRef`. That is enough to stop the routes that recovered a full email in
~300 queries and an exact salary in one: `WHERE`/`LIKE`, `ORDER BY`,
`sum(…) WHERE id = 1`, and the error-channel `CASE`. `SELECT email, id FROM t
WHERE id = 1` still works; the email is projected and masked. Default posture
is unchanged — the inference suite still asserts those routes are recoverable.

`backend_tls = "verify-full"` encrypts and authenticates the proxy-to-database
hop (libpq `sslmode=verify-full`). Optional `backend_ca` adds private CA PEMs
on top of the webpki roots; setting `backend_ca` without `verify-full` is
refused at load so a CA file cannot look like verification while
`require` is still AcceptAny.

Client TLS requirement and the catalog DDL-race retry were already in; this
release does not change them.

## 0.1.71 — CI found a startup bug the local gate never could

Adding CI turned up a real defect on its second green-attempt, and it is not a
test defect.

`resolve_snapshot` scans `pg_class` and calls `pg_get_viewdef(c.oid)` per row.
The scan runs against a snapshot; `pg_get_viewdef` resolves the relation as it
stands *now*. Drop a view in between and it errors on an OID the scan already
returned:

    ERROR: could not open relation with OID 17041

That error is not caught anywhere. `Catalog::resolve` runs **before the proxy
binds**, so a view dropped at the wrong instant stopped pgmask from starting —
and an operator whose proxy will not start routes around the proxy. On refresh
it burns a `failed_refreshes` and keeps a stale snapshot, which is safe but
silent.

`resolve_snapshot_retrying` retries the whole load up to four times with a
short backoff. Retrying the whole load rather than skipping the vanished
relation is what this file already demands of itself: "a half-loaded catalog
has unknown coverage".

The classifier is deliberately narrow — matching the message, because the
SQLSTATE is `XX000` (internal_error) and retrying on that would swallow a bad
DSN, a refused connection, and a permissions error into a slow start with the
reason buried in a warning. Tested both ways, including that the match works
through the `.context("loading view definitions")` chain, which only appears in
the `{:#}` alternate form. A test written against a bare error would have
passed while missing every real case.

WHY SEVENTY RELEASES DID NOT FIND IT

It never reproduced on the development machine. On a Linux runner the window is
wide enough to hit reliably: the first CI run that executed these suites failed
41 of them, and the run after the concurrency fix still failed 6.

That is the argument for CI that the test counts were not making. The local
gate is more thorough in every dimension except one — it runs on one machine,
with one timing profile, and this class of bug is invisible from there.

TWO WRONG TURNS ON THE WAY, BOTH RECORDED

The first CI never ran these suites at all, having reasoned "they need
containers, and containers mean podman" — they need a reachable Postgres, and a
service container is one.

The second removed `PGMASK_ALLOW_SKIP` from the workspace sweep, on the
strength of a doc comment saying "the gate does not set it". The gate does set
it, deliberately, and runs these suites separately with `--test-threads=1`.
Removing it ran all 41 concurrently against one backend — which is how the
underlying race got found, so the wrong turn was productive, but the reasoning
was wrong and the comment that caused it is fixed at the source.

## 0.1.70 — eight gate failures, one bug wearing three costumes

The first full gate run since v0.1.61 finished **13 of 21**. Not one of the
eight failures was a masking defect. All eight were the same instrument bug:
a readiness check that answers before the thing is ready, and falls through
when it never is.

**`pg_isready` is the wrong probe.** The official postgres image runs a
*temporary* server during initialisation to build the cluster. It listens on
the unix socket only, and `podman exec … pg_isready` talks to exactly that
socket. Measured here: `pg_isready` says YES at **3s**, a socket query still
fails at 3s, and the host TCP port is unreachable at **13s**. The temporary
server is then stopped and the real one started, so "ready" is followed by "not
ready" — after the loop has already returned.

Seven suites had their own copy of that loop, and every copy `break`s on
success and falls through on exhaustion, making a timeout indistinguishable
from readiness. That is what skipped `ALTER SYSTEM SET ssl = on` in the TLS
suite: the probe returned during the window, the ALTER hit a socket that was
not accepting, its error went to a discarded stream, and the channel-binding
assertion failed nine steps later reporting that the server refused TLS — true
about the database, nothing to do with the proxy.

The discriminator is that the temporary server is socket-only and the real one
listens on TCP. So `pg_await` waits for a query answered *over the mapped host
port*, which cannot be the init server and proves the exact path the suite is
about to use.

**CockroachDB was not resource-starved.** Four suites failed to start it. Not
memory (6.4 GB free, other containers using 60 MB), not the image (pinned
version, native arch). It is disk latency in the podman VM: with an on-disk
store the init step cannot dial the node it just started and the container
exits 1, while the node's own log reports "node might be overloaded" for 0.5s
raft writes. `--store=type=mem` and it is ready in 20s. These containers are
deleted at the end of the suite, so a durable store bought nothing.

**`sleep 4` is not a proxy readiness check.** pgmask resolves its whole catalog
before it binds, so its startup time scales with the catalog and the machine.
Four suites guessed with `sleep 2`/`3`/`4`; under gate load the guesses expired
and they reported "proxy did not come up" about a proxy that was starting
normally. `proxy_await` polls the connection it is about to use.

ONE DEFINITION INSTEAD OF SEVEN

All three now live in `scripts/lib/container.sh`, the repository's first shared
shell library. The bug existed seven times because the helper did.

Worth recording: `test-versions.sh` had already found the `pg_isready` race and
fixed it locally — its comment reads "pg_isready inside the container can go
green before podman's port forward is live" — and it is the one Postgres suite
that passed, 120 of 120. The knowledge was in the repository and could not
travel, because there was nowhere for it to live.

Verified, not assumed: `test-cockroach.sh` now passes 43 of 43, having failed
to start the database at all.

## 0.1.69 — a configured certificate was optional

**Disclosure 10.** Setting `tls_cert` did not require TLS. Postgres has no ALPN
and no TLS port: a client that never sends `SSLRequest` — `sslmode=disable`,
one flag — got a fully working plaintext session, against a proxy whose own
startup log said `tls=true`.

Not a masking bypass, and worth saying first: the invariant held, and no
unmasked value reached a plaintext client that would not have reached a TLS one.
What failed is the sentence at the top of `tls.rs` — "a masking proxy reachable
over plaintext is not a security boundary" — which the module states and did not
enforce. Masked output is not public output: partial masks are partial by
design, a pseudonym is a stable identifier across queries, and the SCRAM
exchange and the client's SQL cross the same wire.

`client_tls` existed. It decided whether to strip SCRAM channel binding and
nothing else. There was no way to require TLS, no refusal, no warning, no
counter — and `has_client_tls()`, the accessor behind `tls=true`, returned
`self.tls.is_some()`: a fact about the configuration, named like a fact about
the connection. It is now `client_tls_configured()`.

Worse in one specific way: the channel-binding strip *smooths* the plaintext
path, because it exists so pgmask can front a TLS-only managed Postgres. The
downgrade had no friction to run into, so it needed a gate.

`require_client_tls` defaults to **true whenever `tls_cert` is set**.
Configuring a certificate and not requiring it is the shape of a mistake, not of
a decision. `false` allows plaintext deliberately: those sessions warn at
startup and count as `plaintext_session`, because the dangerous configuration is
not "no certificate" — that is a choice — but a certificate any client may
decline. `true` without a certificate is refused at load: it refuses every
connection, which is fail-closed and useless, and reads like the strictest
setting rather than the broken one.

WHY THE SWEEP AND SEVEN PASSING TLS TESTS BOTH MISSED IT

The 08-11 sweep enumerated everything reaching the client and asked what each
could carry. A question about contents. Nothing in it asked what the contents
travelled over, so `tls.rs` was never opened — a blind spot exactly the width of
the method's own framing.

`test-tls.sh` connected with `sslmode=require` in all seven assertions, which is
the right way to test that TLS works and structurally incapable of testing that
it is required. It now runs 18 checks including the downgrade, with a poison
control: with enforcement stubbed out, 7 fail and the 4 opt-out checks still
pass. Verified, not assumed.

AND THE SUITE WAS HIDING A SECOND FAILURE

Its two `pg_isready` loops broke on success and fell through on timeout. Run
next to a soak, Postgres exceeded the 30s budget, `ALTER SYSTEM SET ssl = on`
ran against a socket that did not exist, its error went to a discarded stream,
and the run continued with SSL off — so the channel-binding assertion failed
reporting that the server refused TLS. True about the database, nothing to do
with the proxy. Both loops abort now and `SHOW ssl` is read back.

ALSO

* **Documented: pgmask authenticates nobody.** It forwards the exchange and
  watches for `AuthenticationOk`, so `[[role]]` relaxations are exactly as
  strong as the backend's `pg_hba.conf`. A backend using `trust` makes every
  relaxation self-service. The parts pgmask controls are in place and tested —
  an unauthenticated session gets the most restrictive classification, a startup
  packet naming `user` twice is refused — and none of them help there.
* The disclosure-count invariant hardcoded "nine" and used a regex that could
  not match a two-digit number, so adding number 10 would have left it passing
  while counting 13 of 14 rows: a drift gate with the drift built in. Both
  counts are now derived from the tables.
* The README said 7 TLS checks; that number is now derived from the call sites,
  as the suite count already was.

## 0.1.68 — the assessment had gone stale about itself

A coherence pass over `docs/safety-assessment.md`, which is the document this
repository tells people to read before deploying, and which four releases of
edits had left disagreeing with itself.

It said the gate runs **17 suites**; it runs 21 — four releases after the same
number was corrected in the README, because only the README was checked. Both
documents are checked now.

It said **six disclosures in a single day, four found by reading**. It is nine
over two days across thirteen channels, and *all nine* were found by reading
rather than by any test. Understating that weakens the only argument the section
is making, which is for a second reader.

It credited `test-mutants.sh` with "seven predicates whose only proof lived in a
shell script". That was a partial run. The first complete campaign is 827
mutants — 620 caught, 157 missed, 10 timed out, 40 unviable — and triage of it
produced six real test gaps.

NINE MORE ROWS FOR THE TABLE

The instruments table is the document's central claim, and it was missing every
failure from the second day, including the largest: **the gate's own
`cargo test` could not fail**. Also added — the inference suite grepping for a
message instead of a difference; the campaign miscounting 20,034 SQL errors as
refusals; a length bound standing in for "does not rewrite content"; the shard
that was never requested while the accounting said "814 of 814"; the six ways
the sqlsmith harness reported something untrue; sqlsmith's DML deleting the
fixture; and fourteen releases the changelog called shipped that had no tag.

Twenty-five rows now. The sentence under it — "every one produced a confident
answer about something it was not measuring, and several were built specifically
to prevent that" — has not needed changing.

## 0.1.67 — fourteen releases were never tagged

`git tag` is a separate command from `git commit`, and I stopped running it
after v0.1.52 without noticing for fourteen releases. The changelog said they
had shipped; git disagreed. `git describe` was useless and "what changed between
X and Y" unanswerable.

All fourteen now tagged at the commit that carried each version.

The check requires a tag for every *released* version, where released means "a
commit carried this version in `Cargo.toml`" and not "the changelog has a
heading". Four headings never had a commit of their own — 0.1.17, 0.1.30, 0.1.50
and 0.1.51 were written alongside the release that followed, deliberately in the
last case — and demanding tags for them would invent releases that never
happened.

Derived from Cargo.toml's history rather than kept in an exemption list, so it
cannot go stale the way the list would have. Two exclusions: the current
version, committed a moment before it is tagged, and `0.0.0`, the scaffold
placeholder.

Then I tagged the fix itself `v0.1.67` while `Cargo.toml` still read 0.1.66 — a
tag pointing at a version that did not exist, in the commit that added the check
for exactly that class of mistake. Deleted and done properly.

## 0.1.66 — sqlsmith writes as well as reads, and had been deleting the fixture

The cause of every strange sqlsmith result so far, and it is one line:
**sqlsmith generates DML.** Roughly a tenth of what it emits is a `delete`,
`update` or `insert` against the schema it read.

```text
delete from smith.people
update smith.people set
insert into smith.orders values (
```

A 500-query corpus emptied the table: 200 rows before the replay, **0 after**,
on both sides.

WHAT THIS EXPLAINS

Everything. The canary counts collapsing from 353 to 123 to 1 across runs — the
data was being progressively destroyed. The "no masked value was served" aborts
from round 3 onward — the table was empty. And the false positive in 0.1.65,
where `city` contained `CANARYNAME…`: an sqlsmith `update` had written
`full_name` into it. The fixture was not mysteriously corrupt; the corpus was
rewriting it, and I diagnosed the symptom twice before finding the cause.

**Every sqlsmith figure quoted before this fix was measuring a table being
destroyed underneath it**, including the 353-canary pilot in 0.1.62. Those
numbers should be read as "the harness ran", not as coverage.

THE FIX

`default_transaction_read_only=on` on the replay session. DML is refused, the
SELECTs run, and every round sees the same data. sqlsmith has no flag for this —
`--exclude-catalog` only keeps it out of `pg_catalog`.

Confirmed by the shape of the totals rather than by argument: they now grow
monotonically across rounds — 454, 934, 1498, 2243, 3070, 3601 lines reaching
masked data — where before they shrank toward zero. The fixture check reports
200 of 200 rows intact after six rounds.

Worth stating plainly: pointing a random SQL generator at a database and reading
its output requires knowing whether the generator writes. I did not check, and
spent four rounds of debugging on the consequences.

## 0.1.65 — a leak that was not one, and the check that would have caught it

The sqlsmith soak flagged its second round: **165 canary-carrying lines through
the proxy**, saved corpus, the lot. It was a false positive, and I was one step
from reporting it as a tenth disclosure.

That container's `city` column contained `CANARYNAME…`. `city` is deliberately
*released* by the catalog, so the proxy was correctly passing through an
unmasked column that happened to hold the token the check greps for.

WHAT EXPOSED IT

Bisecting the corpus to a single statement, then running that statement both
ways. The offender was:

```sql
select ref_0.city as c0, ref_0.note as c1 from smith.people as ref_0
where ref_0.born is not NULL limit 151;
```

— which does not select `full_name` at all. Direct returned
`CANARYNAME150|CANARYNAME150`: the canary was in `city`, and `note` came back
correctly nulled. No correct fixture produces that row, and a fresh container
loaded from the same extraction produces `Denver|CANARYNOTE150`.

THE ASSUMPTION UNDERNEATH EVERY CANARY TEST

A canary check is sound only if canaries appear **only** in masked columns. That
had never been verified — the fixture was assumed to be the fixture. Both
scripts now count all 200 rows against their expected values before trusting any
result, and abort otherwise. Poison-controlled with the exact scenario: put a
canary in the released `city` column and the run fails with
`the fixture is not what this test assumes (0/200 rows correct)`.

Five ways this harness has now reported something untrue — four saying "no
leaks" while measuring nothing, and one saying "leak" when there was none. The
tool is worth having. It has needed more scepticism than the code it tests.

## 0.1.64 — the first complete mutation campaign

`attempted 827 of 827`. Five runs were needed to get one that measured the whole
set: two died part-way and printed a tidy summary, one filled the disk, one
skipped shard 0 and errored on shard 20 while reporting "814 of 814", and this
one finished.

```text
  caught     620
  missed     157
  timeout    10
  unviable    40
```

A 79.8% kill rate on viable mutants, against 71.9% for the 19-shard run before
it. Survivors fell from 215 to 157 while *more* mutants were tested — that
difference is the six gaps triage found and closed, which is the first time
today's work has been measured rather than asserted.

By file: `session.rs` 55, `catalog.rs` 45, `mask.rs` 27, `protocol.rs` 14,
`analysis.rs` 12, `lineage.rs` 4. `protocol.rs` came down from 54 as the
channel-binding, result-format and startup-frame tests landed.

Two things stated rather than glossed. The 10 timeouts may be contention: I was
building the sqlsmith harness alongside, which is the thing this file has told
people twice today not to do. And a campaign with survivors exits non-zero —
that is cargo-mutants saying "there are mutants to triage", not "the harness
broke", and the script now says so next to the summary, because `EXIT=3` on an
otherwise complete run reads like a failure.

## 0.1.63 — the foreign grammar, for hours instead of seconds

`soak.sh` runs `shapegen` for hours. `soak-sqlsmith.sh` does the same with
sqlsmith, which is the distinction that matters: running my own grammar longer
explores more of what I already thought of, and before v0.1.36 no amount of that
would have reached two of the six original disclosures.

One container for the run and a fresh seed each round. sqlsmith builds from
catalog OIDs, so a new seed against the *same* catalog is what varies the
corpus — recreating the container per round would be slower and would change the
OIDs, making a seed meaningless as a label.

EVERY ROUND CHECKS ITS OWN CONTROLS

A round that reaches no masked data, or serves no masked value, **aborts the
run** rather than being counted. That is not caution for its own sake: the
single-shot version of this reported zero leaks four times in a row while
measuring nothing, and a long campaign averages such rounds into a total that
looks like evidence. Half a million statements are worth less than they appear
if some unknown fraction of the rounds never reached a masked column.

The schema, catalog and control statements are lifted out of
`test-sqlsmith.sh` rather than duplicated, so a finding here reproduces with the
single-shot suite, and the two cannot drift into testing different things.

On a leak the offending corpus is written to
`/tmp/pgmask-sqlsmith-leak-<seed>.sql` — the seed alone does not reproduce it,
so the statements themselves have to be kept.

## 0.1.62 — SQL from a grammar nobody here wrote, and four ways it said nothing

Every campaign here generates from `shapegen`, which I wrote. That is the
sharpest criticism of all the evidence in this repository, and it is not
hypothetical: before v0.1.36 the generator could not express `SELECT * FROM (…)`
or `GROUPING SETS`, so two of the six original disclosures were unreachable by
it no matter how long it ran.

sqlsmith reads the live catalog and builds semantically-valid random queries
against whatever it finds. Hundreds of real PostgreSQL bugs to its name, and no
opinion about which shapes are interesting here.

FOUR WAYS THE HARNESS REPORTED ZERO LEAKS WHILE MEASURING NOTHING

1. **Pointed at the proxy, sqlsmith finds no tables.** It introspects
   `pg_catalog`, which the proxy refuses, so it generates nothing — and that
   reads as a clean run. It generates against a direct connection instead.
2. **Releasing one column as a poison does not fire.** A 150-query corpus may
   never touch that column, so the control was consistent with both a working
   harness and a blind one.
3. **Releasing *every* mask still does not fire.** sqlsmith writes
   expression-heavy SQL and the proxy refuses any field without column
   provenance whatever the catalog says. A corpus of refusals looks exactly like
   a corpus being masked correctly.
4. **Control statements appended to the corpus never ran.** Several refusal
   paths set `out.close = true`, psql then fails everything after that point,
   and anything at the end of a long corpus is never reached. This also explains
   direct canary counts of 353, 123 and 1 across runs at the same seed: each
   replay died at a different statement.

WHAT IT ASSERTS NOW

The corpus must reach masked data — the direct replay has to surface canaries.
Masked values must be *served* through the proxy, or nothing observable
happened. And no canary may cross. Five plain provenance-bearing statements run
in their own session so a closed connection cannot take the controls with it.

Verified both ways: clean is 35 canaries direct, 0 proxied, 32 masked values
served; releasing every mask puts **47 canary-carrying lines** through the proxy
and fails.

Also recorded: `--seed` does not reproduce a corpus, because sqlsmith builds
from catalog OIDs and those differ per container. Each run is an independent
sample, not a repeatable one.

The gate is 21 suites.

## 0.1.61 — a lineage method that looks load-bearing and is consulted by nothing

The last untriaged survivor group: four value-replacing mutants on
`SnapshotCatalog::list_columns`, in the module where under-reporting a source
column is a *disclosure* rather than a utility cost. Worth checking properly
rather than assuming.

They are equivalent, and the evidence is that replacing the method with `None`,
an empty list, or `["xyzzy"]` changes the verdict of no shape at all:

```text
  SELECT upper(ship_city) FROM demo.orders                     Release
  SELECT upper(c.city) FROM …customers c JOIN …orders o ON …   Release
  SELECT upper(city) FROM …customers JOIN …orders USING (id)   Release
  SELECT * FROM demo.orders                                    Unresolved
  SELECT upper(x.ship_city) FROM (SELECT * FROM …orders) x     Unresolved
  WITH q AS (SELECT * FROM …orders) SELECT upper(ship_city)    Unresolved
```

Identical under all four. A column list is wanted for star expansion, and every
star shape is already `Unresolved` — guard 2 refuses an empty source list —
before the answer could matter. Named columns resolve without it, including the
`USING` join where a bare column has to be attributed to one of two tables.

Kept correct rather than stubbed. It is a `sqllineage` implementation detail
rather than a contract, and a version bump could start consulting it — the same
reasoning as the `FuncCall` guard that no engine can currently reach. The
docstring records the six shapes as what was measured, not a proof over all SQL.

That closes the triage of the 19-shard campaign: six real gaps fixed, and the
rest equivalent, unreachable, or not safety-relevant, each said so in the place
someone would next look.

## 0.1.60 — the Luhn floor, where a relaxed bound leaves a card in the text

`is_luhn` is the `Scrub` mask's card detector, and `Scrub` is the one mask that
**reveals by default** — its own doc says a gap is a disclosure rather than a
utility cost. Its `digits.len() < 13` floor had no test on either side.

`<= 13` stops redacting the 13-digit Visa and 14-digit Diners formats, which
then stay in a support note a human reads. Pinned with numbers that are
Luhn-valid at 12 and 13 digits, so only the bound can decide them, plus the
`scrub_free_text` level so the redaction itself is checked and not just the
predicate.

AND ONE THAT IS GENUINELY EQUIVALENT

The campaign also reports `doubled > 9` relaxed to `>= 9`. It cannot matter:
`doubled` is `d * 2` for a digit, so it is always even and never 9. Predicted
before running the control, and the control agrees — it is the only one of the
three that does not fire. Written on the line rather than left for the next run
to re-raise.

Three predictions, three confirmations: `<= 13` a real gap in the disclosing
direction, `== 13` a behaviour change in the safe direction, `>= 9` equivalent.

## 0.1.59 — a pseudonym whose local part was never looked at

Both email branches of `Masker::pseudonym` slice
`digest[..PSEUDONYM_HEX_CHARS / 2]`, and every mutation of that arithmetic
survived. `/` to `%` gives `digest[..0]` — an **empty local part**, so every
address at a domain masks to the same value and joins collapse silently.

Under `keep_domain` there was one assertion and it was
`ends_with("@acme.com")`, which passes with an empty local part, a doubled one,
or anything else. The collision test that would have caught it uses
`subject-{i}` — no `@` — so it exercises the non-email branch only.

Now the local part is checked: sixteen hex characters, and two addresses at the
same domain must differ. The default branch too, where the domain is masked as
well. Two poison controls; the empty-local-part one fails four tests, because
collapsing every colleague onto one pseudonym breaks rather more than the test
that names it.

Not a disclosure — a narrower pseudonym leaks nothing, and an empty one leaks
less. It corrupts the thing the mask exists to preserve, which is that a join
still works after masking.

## 0.1.58 — the startup frame, where `<= 8` breaks TLS for everyone

`try_take_startup` is private, so no cargo test reached it and every boundary
mutant survived: `< 8` to `<= 8`, `< len` to `<= len`, and deleting the `!` from
the plausibility check. The TLS script does exercise this path — but
`cargo mutants` runs `cargo test`, not scripts, so the only coverage there was
invisible to it.

`<= 8` is the one that matters. **An `SSLRequest` is exactly eight bytes**, so
that mutant makes the reader wait forever for a ninth and TLS negotiation stops
working for every client. Not a disclosure; an outage, and the kind that looks
like a network problem.

One test, covering: an eight-byte `SSLRequest` taken whole and consumed; seven
bytes returning `None` without consuming anything and without erroring; a frame
whose body has not all arrived left untouched rather than truncated; the same
frame complete; and lengths of 0, 7, 1048577, -1 and `i32::MIN` refused rather
than trusted.

Three poison controls, all firing.

I got the fixture wrong first — asserted `&body[..9]` against a ten-byte
`user\0alice`. The test failed on its own arithmetic before it could test
anything, which is the cheap version of this mistake.

## 0.1.57 — the result-format codes were only ever checked for not panicking

`parse_bind_result_formats` and `format_for` decide whether each output field is
text or binary, and the masker branches on that. Every value-replacing mutant
survived — `Some(vec![])`, `Some(vec![0])`, `Some(vec![1])`, `None`, and
`format_for -> 1`.

The reason is visible once you look at what touches them:

```rust
let _ = parse_bind_result_formats(&body);
let _ = format_for(&formats, index);
```

Both are reached only by the never-panics properties, which assert nothing about
the answer.

AND NOTHING ELSE WOULD HAVE CAUGHT IT

The canary fixture is entirely text columns, and for text-family types the text
and binary encodings are **the same bytes** — `MaskSpec::supports` says so, and
it is why the string masks accept both formats. So a wrong format changes
nothing there. It changes everything for a date, a numeric, or a uuid, and those
live in the demo, which `cargo mutants` does not run.

Two tests. One pins the protocol rule that a *single* result-format code governs
every column rather than only column 0 — the subtlety a constant-returning
mutant hides — and that more columns than codes means text rather than reusing
the last one. The other reads the codes out of a `Bind` that actually carries
parameters, because the codes come after them and a parser that does not step
over a parameter by length reads them out of the middle of a value.

Four poison controls, one per rule, all firing.

## 0.1.56 — the functions that decide whether authentication downgrades

Triaging the campaign's survivors, `session.rs` had 69 and two of them were the
guards on the SASL channel-binding arms. Following those:
`strip_channel_binding` and `sasl_mechanisms` had **no test anywhere** — not a
unit test, not a suite, not the demo. Nothing in the repository mentioned
`-PLUS`, `Cause::ChannelBinding`, or either function outside its own definition.

They matter because the proxy terminates TLS. Postgres advertises `-PLUS` on its
own TLS leg, a client cannot satisfy channel binding against a certificate the
proxy holds, and stripping is the only way a plaintext client connects at all.
Wrong in one direction breaks every login; wrong in the other strips for a TLS
client, which the server correctly reads as the downgrade attack it is.

Three tests, and three poison controls that each fail one: stripping when there
is no `-PLUS` to strip, keeping the `-PLUS` mechanism, and reading any
authentication message as a mechanism list.

THE THIRD POISON NEEDED A BETTER FIXTURE

It did not fire at first. The test used `AuthenticationOk` as the non-SASL case,
and that body has no payload — so misreading it still yields an empty list and
the assertion passes either way.

`AuthenticationMD5Password` carries a four-byte salt, and a salt containing a
NUL reads as a perfectly good mechanism name if nothing checks the sub-code is
10. That is the fixture that makes the check load-bearing, and it is the same
lesson as every other control in this file: a negative case has to be one that
could actually come out wrong.

MOST OF `session.rs`'s SURVIVORS ARE NOT THIS

Fourteen of the 69 are the `session closed` log line's condition — whether a log
line is emitted, with nothing asserting the log. Six more are the
`UnexpectedEof` arm in connection teardown. Worth saying so rather than letting
a survivor count read as 69 gaps.

## 0.1.55 — the completeness check had the hole it was built to close

The campaign finished and reported `attempted 814 of 814`. It had run 19 shards
of 20.

```text
error: invalid value '20/20' for '--shard <SHARD>': shard k must be less than n
```

`--shard k/n` is 0-indexed. The loop ran `seq 1 $SHARDS`, so **shard 0 was never
requested** and shard `20/20` was rejected — about a tenth of the mutants, never
tested. Verified after fixing: shards 0..19 of `analysis.rs` sum to 197, which
is exactly its unsharded count. The old range summed to less and nothing said so.

WHY THE ACCOUNTING MISSED IT

This is the check added in 0.1.39 after two runs reported a fifth of a campaign
as a whole one. It compares mutants planned against mutants attempted, summed
across shards — and a shard that fails to start contributes **zero to both
sides**. The totals agree, the run reads as complete, and the one case the check
cannot see is the case that happened.

So the count is now checked per shard, at the point where a zero is still
attributable, and the message says why it is caught there rather than at the
end.

A guard against vacuous success, with a vacuous success in it. Third time in
this project that the instrument and the defect have been the same shape.

WHAT THE PARTIAL RUN SAYS ANYWAY

550 caught, 215 missed, 12 timed out, 37 unviable, over 90% of the mutant set
with nothing else on the machine — so the 12 timeouts are real rather than
contention. The survivors are worth triaging and are not a complete list; the
assessment says so.

## 0.1.54 — and the disclosure count, including the one I got wrong fixing it

The README said "what six disclosures were found in a single day" for four
releases after there were nine. Fixed.

Then, in the sentence explaining that 7 and 9 have sub-parts, I wrote that the
channel count "is fourteen" — without counting the rows. It is thirteen: six in
the release rules, seven in the diagnostic and `ParameterStatus` channels. In a
document whose subject is numbers asserted with more confidence than the
measurement behind them.

So both get a check rather than a promise. `check-repo-invariants.sh` counts the
table rows in the assessment and requires two things of the prose: that the
README's disclosure count is the current one, and that the assessment's own
channel figure matches its own tables. Two poison controls, both reporting the
real number rather than the claimed one.

The convention is now stated where the tables are: **nine** is the numbering,
**thirteen** is the count of ways a value got out.

## 0.1.53 — the front page undercounted the gate by a third

> `./scripts/test-all.sh` runs thirteen suites … 265 cargo tests, 31 adversarial
> and resilience tests, 88 demo assertions, 7 TLS, 115 across Postgres 13-17,
> 34 against CockroachDB, a 44-shape canary sweep …

Every number there was stale. The gate runs 20 suites and 505 cargo tests, with
40 adversarial and resilience, 98 demo assertions, an 18-check `classify` round
trip, 120 across Postgres 13-17, 43 against CockroachDB and an 86-shape sweep.
It drifted over seven releases and nothing looked, because nothing was looking
at prose.

This is the same class of wrong as a test that does not run, aimed at a person
rather than a machine — and the direction matters less than it seems. A front
page that *undercounts* still misleads: it is the first evidence a reader has
about how much scrutiny the thing has had.

`check-repo-invariants.sh` counts the gate's suites — every `record "…"` that is
not the `run()` helper's own, plus every `run "…"` — and requires the README to
say the same number. The README says `20` as a digit so the check can find it,
and the check reports both numbers rather than the first draft's
"README does not say the gate runs 20 suites; it runs 20."

Two poison controls: a wrong number, and no number at all.

Also added there: a line recording that the counts come from a run with nothing
else on the machine, because several suites are timing-sensitive enough to
report false failures under load — which happened twice today, to me.

## 0.1.52 — the gate's containers, and three failures I caused myself

Two gate runs failed the same three container-heavy suites — the Postgres
version matrix, the generated campaign, and the CockroachDB shape run. The
detail, once I stopped overwriting it:

```text
==> poison run: masking removed, the oracle must fire
FAIL: masking was removed and nothing leaked — the oracle is not working
Error: connecting to the proxy … Connection refused
```

The negative control could not reach its proxy, because I was running
`test-cockroach.sh` and `test-classify-roundtrip.sh` in another shell while the
gate ran. Those tear down proxies and containers *by name*, so each run was
destroying the other's. Both "failures" were mine.

The gate already refuses to start when a `pgmask` process is running, for this
exact reason. It did not look at containers, which is the other resource its
teardown assumes it owns. Now it does, split by how bad the collision is:

* **Hard** — a container the gate removes by name. It will be destroyed mid-use
  and its ports taken. Refuse.
* **Soft** — any other `pgmask-*` container, `pgmask-mutants` being the case.
  Not destroyed, but competing for CPU and disk, and a campaign will take a
  machine's worth of both. Say so, so the next person does not read timing
  failures as real.

`pgmask-roundtrip` was also missing from the per-suite teardown list, which is
how a leftover container from a `KEEP=1` run made the round-trip suite fail with
"postgres did not start" — its own previous container held the port.

WHAT I DID WRONG, BEYOND THE OBVIOUS

I redirected both gate runs to the same `/tmp/gate.log`, so the second destroyed
the first's evidence and I spent a round unable to diagnose a three-suite
failure that the gate had already printed in full.

And I edited `scripts/test-all.sh` while a run was executing from it. Bash reads
a script incrementally; the hazard is documented in this repository for
`test-mutants.sh` and I walked into it anyway.

## 0.1.51 — the drift gate passed on a schema that did not exist

`classify --check` is what operators are told to put in CI. Nothing exercised
it: no script ran it, and it cannot be unit-tested because it compares a catalog
file against a live schema.

```console
$ classify --check --catalog catalog.toml --schema definitely_not_a_schema
catalog catalog.toml vs schema `definitely_not_a_schema`
  columns in the database   0
  rules covering them       0

every column has a rule and every rule matches. no drift.
$ echo $?
0
```

Zero columns satisfy every assertion it makes, vacuously. A typo in a schema
name, a DSN pointing at the wrong database, or a migration that dropped the
schema all produced a green build that checked nothing — the exact failure this
tool exists to catch, in the tool itself. It fails now, and says which of the
two causes to look for.

AND A FRESHLY GENERATED CATALOG DOES NOT PASS IT

Found by writing the test and asserting the opposite, which I believed.

`classify` emits no rule for a column it judged ordinary — deliberately, because
its own report says nothing verified those are harmless, so `mask = "none"`
would be the tool claiming exactly what it disclaims. `--check` then reports
them as undecided, because default-deny masks them and somebody finds out when a
dashboard goes blank.

So the loop is: generate, decide the ordinary columns explicitly, then put
`--check` in CI. Both ends are now asserted, and `docs/responsibilities.md` says
so where the `--check` instructions are, rather than leaving an operator to
discover it from a red build on day one.

Eight checks on the drift gate, where there were none. The round-trip suite is
18.

## 0.1.50 — the diagnostic fixes, on the other engine

The 2026-08-11 disclosures were found and fixed against Postgres. The fixes are
wire-level — `LEAKY_FIELDS`, the withheld primary message, the `ParameterStatus`
allowlist — so they *should* hold for anything speaking the protocol. "Should"
is the reason this exists.

Measured on CockroachDB v25.4.14, and the answer is not uniform:

| channel | on CockroachDB |
|---|---|
| `RAISE EXCEPTION '%', (SELECT email …)` | carries the value, same as Postgres |
| `RAISE NOTICE` | same |
| `USING DETAIL`, `USING HINT` | carry the value |
| `CONTEXT` traceback | **does not exist** — a DO-block error reports only `LOCATION` |
| dynamic SQL into a traceback | **unimplemented** — `stmt_dyn_exec is not yet supported` |
| `scram_iterations` | not a CockroachDB setting |

Five checks added for the four channels that are real, each with a control
proving the engine carries the value before asserting the proxy does not — the
suite is 43 checks now, up from 34.

The three that do not exist are deliberately *not* checked. A refute against a
channel the engine cannot open passes forever and reads as coverage, which is
the failure this project has hit more often than any other.

Two poison controls: restoring the error-message leak fails two checks, and
dropping `D` and `H` from `LEAKY_FIELDS` fails two more. Dropping `W` fails
nothing here, correctly — there is no `CONTEXT` on this engine to drop.

## 0.1.49 — the TOML classify writes had never been given to pgmask

`classify --check` compares an existing catalog against a live schema.
`validate_spec` checks a `MaskSpec` in memory. Neither of them ever took the
actual artefact — the file a person copies out of their terminal — and fed it
back to the thing that has to read it.

That is the seam where a change in one crate breaks the other in silence.
`classify` learned to emit `range` with `start`/`end` for postcodes two releases
ago, and whether `pgmask` accepts that combination was a matter of reading two
files and believing they agreed.

`test-classify-roundtrip.sh` does the thing an operator does: run `classify`,
prepend the four connection lines it cannot know, start the proxy with the
result, and query through it. Ten checks, and three poison controls — emitting
`bucket = 1`, emitting an empty `range` window, and reverting the postcode mask
to `partial` — each fail it.

TWO FINDINGS FROM WRITING IT, BOTH MINE

The first control column was `city`, and it came back `***`. `classify` matches
`^city$` with its `geo` rule, so it was classified, not unclassified — a control
has to be a name no rule matches. It is `warehouse_label` now.

And the salary assertion failed because the salary was 68000 under a bucket of
1000. The mask had worked exactly as specified: **bucketing returns a value that
sits on a bucket boundary unchanged.** Inherent rather than a defect, but worth
knowing before choosing a bucket — one value in `bucket` is disclosed exactly,
and round numbers are commoner in real salary data than a uniform distribution
suggests. Written onto `Mask::NumericBucket`, where the `bucket >= 2` rule
already lives for the degenerate case of that same property.

## 0.1.48 — a shard is a disk budget, measured this time

The campaign filled the disk and died at shard 8 of 12. The accounting caught
it — `attempted 520 of 552`, exit 1, "missed.txt is not the survivor list, do
not triage it" — which is the third partial run that guard has refused to let
pass as complete, and the first where it also stopped me acting on the results.

WHY THE BETWEEN-SHARD CHECK NEVER GOT A TURN

It was set at 6 GB, and a shard of 65 mutants took the free space from 13 GB to
2 GB in one go. cargo-mutants rebuilds the tree copy per mutant and its target
directory accumulates, reclaimed only when the shard ends — so a floor that does
not cover a *whole shard* is a floor the run walks straight past.

Measured at roughly **0.17 GB per mutant**. Twelve shards was 69 each, about
12 GB. Twenty shards is ~41 each, about 7 GB, and the floor is 15 GB so a shard
plus a concurrent `cargo build` still fits. The numbers are in the script rather
than in my head.

WHAT ELSE ATE THE DISK

`cargo clean` on this repository freed **49.5 GB** — `du` had been reporting 34.
The gate rebuilds with incremental compilation on, and I had been running it
repeatedly alongside the campaign, which is a large part of why the margin
vanished. The mutants script sets `CARGO_INCREMENTAL=0` for its own runs; the
gate does not, deliberately, because iteration speed is worth it there.

Standing recommendation for whoever runs this next: do not run the gate and the
campaign at the same time. They compete for the same disk and the campaign is
the one that dies.

## 0.1.47 — triaging the rest: three tests, two comments, one measurement

Continuing through the survivor list. The useful output of a mutation campaign
is not a number, it is a decision per mutant, and there are three decisions.

A REAL GAP: EVERY PARAMETER GUARD BUT ONE WAS UNTESTED ON ITS EDGE

`outer`'s `keep = 0` had a boundary test. `numeric-bucket`'s `bucket < 2` and
`range`'s `end <= start` did not, and the campaign reported `< 2` -> `<= 2` and
the whole `range` guard -> `true` as surviving.

Over-rejection here is fail-closed, and it would also mean the catalog
`classify` writes no longer loads: it emits `bucket = 1000` and
`start = 2, end = 64`, and nothing connected the two crates. Both edges of both
guards are pinned now, including those exact values, and three poison controls
fire.

UNREACHABLE, AND MEASURED RATHER THAN ASSERTED

`grouping_may_reference` refuses a `FuncCall` in a grouping element that carries
`OVER`, `FILTER`, an ordered-set clause or `count(*)`. Turning any of those `||`
into `&&` breaks no test — because the engine rejects the statement first:

```text
  GROUP BY sum(id) OVER (PARTITION BY id)
    ERROR: window functions are not allowed in GROUP BY
  GROUP BY count(*) FILTER (WHERE id > 0)
  GROUP BY string_agg(email, ',' ORDER BY id)
  GROUP BY count(*)
    ERROR: aggregate functions are not allowed in GROUP BY
```

A statement the engine refuses cannot disclose. The guard stays — the walker's
contract is "return None for anything that could reference more than it appears
to", and an engine that one day allows one of these should meet a guard rather
than a gap — but it is defence in depth and now says so.

EQUIVALENT: THE DEPTH CAPS

`depth > 24` and `depth > 16` both survive relaxation to `==` or `>=`. Every
path increments — `d = depth.saturating_add(1)`, passed to every recursive call,
which I checked because several call sites read as passing `depth` unchanged —
so all three still cap, one level earlier or later. Telling them apart needs an
expression nested exactly 24 deep, and the number is a stack guard rather than a
property. What matters is that the cap refuses, and that is tested.

## 0.1.46 — the campaign's first real finding, and two mutants that are not one

Triage of the 827-mutant campaign, at the halfway mark. Three categories, and
the interesting thing is that they are genuinely different from what a day of
reading found.

TWO UNTESTED BOUNDARIES, IN THE DISCLOSURE DIRECTION

`partial`, `inner` and `outer` floor a value that is too short for the window
they keep: `checked_sub(...).filter(|n| *n > 0)`. Relaxing that to `>= 0` at
`len == keep` — or `keep * 2` for `inner` — makes the masked run zero characters
long, so `partial` emits the whole value and `inner` emits head plus tail, which
is also the whole value.

Both survived. Every existing test sat strictly inside or strictly outside the
window and none sat *on* it. A four-character value under `keep = 4` would have
come back verbatim.

`outer` at the same boundary is an **equivalent** mutant: `kept = 0` gives
`"*" * keep` twice, which is exactly the `len` stars the else branch produces.
Said so on the function rather than leaving it to be re-derived.

And `truncate_date_text`'s `year > 9999` survived relaxation to `>= 9999`: the
refusal tests use 10000 and 5874897, the acceptance tests use 2024, nothing sat
on the edge. Over-refusing 9999 would be safe and still wrong — jiff represents
it.

This is what mutation testing is for, and it is a different class from the nine
disclosures: those were missing *cases*, these are untested *boundaries* in
logic that exists.

FOUR MUTANTS THAT ARE NOT A FINDING

`resolve_snapshot` returns early when `rules.is_empty()`, building a second
`Snapshot`, and the campaign reports all four of its fields as deletable with
nothing noticing.

They are equivalent on that path. With no rules nothing is classified, so
default-deny answers every question before those fields are consulted:
`opaque_views` refuses a read that is masked anyway, `unique_keys` only
qualifies a summary and a summary needs a released column, `relation_columns`
backs "does this mention a masked column" and there are none. The one that could
differ is `system_relations` under `system_catalogs = "allow"`, and that
direction is over-refusal.

`an_empty_catalog_masks_everything_and_still_refuses` is added anyway, because
the property is real and was untested — an operator whose catalog failed to load
is exactly who default-deny is for. **It does not kill those mutants**, verified
by poisoning all four; claiming otherwise would be the same mistake as a
green suite that never ran.

A NOTE ON THE CAMPAIGN'S OWN VALIDITY

cargo-mutants copies the tree when it starts, so these results are against
v0.1.43 and not the current tree. `delete field unique_keys` was a genuine
survivor there and is caught now by the v0.1.44 work — confirmed by patching
both construction sites rather than assumed. Anything triaged from this run has
to be re-checked against the tree it will be fixed in.

## 0.1.45 — `SET ROLE` does nothing here, and nothing said so

Before this, no test, script or document in the repository mentioned `SET ROLE`.

`[[role]]` maps a startup principal to pgmask role names, resolved once at
`AuthenticationOk` and never revisited, so `SET ROLE`, `SET SESSION
AUTHORIZATION` and `RESET ROLE` change what the database will let a session read
and change nothing about which mask pgmask applies.

That is the safe direction — a client cannot switch into another role's looser
mask — and it is not what the name suggests. An operator who granted someone a
Postgres role expecting the mask to follow would be configuring nothing, and
would find out from a leak rather than from an error. The README says so now, in
the same section as the promise it qualifies.

Pinned by a test whose fixture is the shape that would matter: a role whose
`by_role` mask *releases* the column, and a principal who is not a member. Four
attempts to reach it — `SET ROLE` to the connecting user, `SET ROLE` to the
privileged role, `SET SESSION AUTHORIZATION`, `SET LOCAL ROLE` — and none does.

The control is half the test: `start_proxy_as_member` connects a principal who
*is* a member and asserts the value comes through in the clear. Without it,
"the canary did not appear" is equally consistent with the role's mask never
releasing anything. Both directions poison-controlled — granting membership
produces a real leak the test catches, and breaking the control fails with "the
`analyst` mask must actually release, or this test asserts nothing".

## 0.1.44 — disclosure 1 again, through the other half of the guard

Disclosures 1-4 and 6 were spellings of the *grouping*. These are spellings of
the *uniqueness*.

The singleton-group guard refuses `sum(x) GROUP BY <unique key>` because one row
per group makes the sum the value. It reads declared keys from `pg_index`, and
two shapes were invisible to it. Both returned `987654321` — the exact value —
through the proxy.

`UNIQUE (lower(label))`. `indkey` holds `0` for an expression, and the query
inner-joined it to `pg_attribute`, so a pure expression index matched no
attribute, produced no group, and vanished. `lower(label)` unique implies
`label` unique, so `GROUP BY label` is provably one row per group from the
catalog alone — it was decidable and simply was not being read.

`UNIQUE (label) WHERE label IS NOT NULL`. Partial indexes were excluded, reasoned
as "they are only unique over the rows matching their predicate". True, and an
argument for the opposite conclusion: a key makes the guard *refuse*, so leaving
one out is the releasing direction.

THE FIRST FIX WAS MUCH WORSE THAN THE BUG

`pg_depend` gives the exact base columns of an index, so the obvious move was to
replace `indkey` with it. That took the generated campaigns from 0 leaks to
**480 and 660**.

A constraint-backed index — every `PRIMARY KEY` and every `UNIQUE` constraint —
has no direct index-to-column dependency at all. The dependency runs through
`pg_constraint`. Measured on Postgres 17: `pg_depend` returns nothing for
`t_pkey` and `t_u_key`, and the columns only for a plain `CREATE UNIQUE INDEX`.
So nearly every real unique key vanished and the guard stopped firing on almost
every table.

Caught by the campaigns, which is what they are for. Nothing else in the gate
noticed — the adversarial suite went on passing, because its fixture indexes are
the shapes I had just been thinking about rather than the ordinary ones.

The design that is actually right: `indkey` is the source, always, and
`pg_depend` only *adds* the base columns of expressions, and only for
non-partial indexes — a partial index's predicate columns are dependencies too,
and `UNIQUE (label) WHERE salary > 0` yields `label,salary`, wider than the
truth, which releases.

A `PRIMARY KEY` and a `UNIQUE` constraint are now fixtures in their own right,
so removing the `indkey` arm fails a test rather than a campaign.

THREE WAYS THIS TEST NEARLY MEANT NOTHING

`max(salary)` instead of `sum`: `max` can return a stored value whatever the
grouping, so it is refused unconditionally and every case came back refused,
including the ones that leak.

No served control: with everything refused, "refused" proves nothing. Adding a
grouping with no unique key behind it is what showed the fix was not a blanket.

And the control column named `label`: unique keys are held unscoped — a flat
list of column-name sets, deliberately, because `group_by_columns` yields bare
names — so a key on *any* relation refuses that name everywhere. That made the
control refuse, and separately let the partial index on one table satisfy the
expression-index case on another, so reverting half the fix broke nothing.
Renaming the fixture columns is what made both halves poison-controllable.

## 0.1.43 — a postcode mask that kept the identifying half

`classify` proposed `partial` for anything matching `zip|postal|postcode`, and
emitted `keep = 4` alongside it. `partial` keeps the *last* characters. A
five-digit US ZIP came back as `*1234`.

Four of five characters, and the wrong four: the leading digits of a ZIP are a
broad region, the trailing ones narrow it to a neighbourhood. The mask kept
exactly the part that identifies.

Now `range` from offset 2, which keeps the coarse prefix — `94103` -> `94***`,
`SW1A 1AA` -> `SW******`, `K1A 0B1` -> `K1*****` — and masks outright anything
shorter than the window. The emitted `end = 64` reads as nonsense until you know
`end` is clamped to the value's length, so a test in `mask.rs` pins those exact
shapes: the proposal lives in one crate and the clamp in another, and if the
clamp ever stops clamping, a postcode column starts arriving verbatim.

FIVE OF SEVEN TEXT-ONLY MASKS WERE UNCHECKED

Found while making that change. `mask_fits` decides whether a proposed mask can
apply to a column's type — it exists because TPC-DS has `c_birth_year` as an
integer and a date mask cannot decode an int4. It had arms for `partial` and
`redact` and fell through to `_ => true` for `inner`, `outer`, `range`, `hash`
and `scrub`.

So `--check` accepted any of those on an integer column, and the proxy refused
the result set at runtime — the outage the function exists to prevent, for five
of the seven masks it applies to. Noticed only because `range` had no arm and I
was about to propose it.

A HAND-WRITTEN LIST, DRIFTING ON CUE

`every_pattern_compiles_and_every_mask_is_one_pgmask_knows` checked rule masks
against an array of mask names typed out by hand. Moving `postal_code` to
`range` failed it: the mask was valid, the list had never heard of it.

The list is derived from the type now, and a `Mask` variant that `ALL_MASKS` has
not been told about fails to compile rather than passing a test that quietly
covers one fewer mask.

## 0.1.42 — the allowlist was right and was reviewed with the wrong question

`ParameterStatus` is governed by an allowlist of GUC names, written after
`application_name` was found carrying a masked address. Twelve names, each one
checked for whether a client can set it.

None was checked for what *shape of value* it accepts.

```sql
DO $$ BEGIN PERFORM set_config('scram_iterations',
         (SELECT annual_salary FROM demo.employees LIMIT 1)::text, false); END $$;
```

`scram_iterations` takes an arbitrary integer over a 31-bit range, so it carried
the number verbatim in a `ParameterStatus` that no `RowDescription` governs.
Measured: `987001`, derived from a masked column, arrived through the proxy.

Every other entry is a boolean, a fixed vocabulary, an existing role name, or
server-fixed — a few bits each, the covert-channel category the assessment puts
out of scope. `scram_iterations` was the only one that carries a *value*, and it
fits any integer-valued masked column: a salary, an age, a count.

Removed. What that costs: libpq reads it to hash a new password client-side and
falls back to 4096 without it. Setting a password through a masking proxy is not
the workload this is for.

THE CONTROL WAS THE HARD PART

The first probe used `SELECT set_config(...)` and reported all four GUCs clean.
They were clean because the proxy refuses that statement outright for having no
provenance — nothing had run. Including a reportable GUC set to a *constant* as
a positive control is what exposed it: the control came back empty too, and an
empty control is the tell.

The test keeps that control and fails on it explicitly — "the control did not
arrive, so nothing below is being tested" — verified by pointing it at a
withheld GUC.

NOT IN THE DEMO, AND WHY

`examples/demo/verify.sh` does not check this. psql never surfaces a
`ParameterStatus`, and the only way to observe one from a psql script is `SHOW`,
which is a provenance-free result set the proxy refuses — so a check written
there passes whether the channel is open or closed. It lives in the adversarial
suite, which reads the wire directly. Writing a check that cannot fail would
have been worse than writing none.

## 0.1.41 — my own fix, one hour old, with the same hole in it

`from_user_sql = !notice && has_field(body, b'W')`.

That `!notice` was written while thinking about errors. `RAISE NOTICE 'x' USING
ERRCODE` takes an expression exactly as `RAISE EXCEPTION` does, so the SQLSTATE
channel closed in 0.1.40 stayed open through `NOTICE`, `WARNING` and `INFO` —
measured, five characters of the canary came back through all three.

The notice is the *worse* of the two. It does not abort the transaction, so

```sql
DO $$ BEGIN FOR i IN 1..10 LOOP
  RAISE NOTICE 'x' USING ERRCODE = <five characters of the value>;
END LOOP; END $$;
```

carries the whole value in a single statement, where the error variant costs one
query per five characters. Withholding it costs nothing: a notice's text is
already replaced unconditionally, so its SQLSTATE has nothing left to qualify.

Found by re-reading the fix rather than by any test, which is the fourth time
that has been the finding method here and the second time in one day that the
thing being re-read was mine.

WHERE THIS STOPS

Written into the assessment rather than left implied, because otherwise these
fixes read as claiming more than they deliver.

What they close is the direct echo of value *bytes* — a message written by
`RAISE`, a `CONTEXT` reproducing a dynamic statement, a `SQLSTATE` set from
`upper(substr(email, 1, 5))`.

What they do not, and no wire proxy can: a client that can execute a `DO` block
with a loop can *encode* a value into anything the protocol lets it vary — how
many notices it emits, which severity each carries, how long the statement
takes, how many rows come back. Severity alone is about two bits per notice and
a loop emits as many as it likes. Closing that means refusing `DO` blocks and
user-defined functions outright, which is a different product.

The line is whether the channel carries the value or carries a message the
attacker encoded. pgmask stops the first.

## 0.1.40 — the notice disclosure again, through the error message

`RAISE NOTICE '%', (SELECT email …)` returning the address was found, fixed, and
checked in both directions in the demo. `RAISE EXCEPTION` is the same channel
through the other message type, and it was open.

```
DO $$ BEGIN RAISE EXCEPTION '%', (SELECT email FROM canary.subjects LIMIT 1); END $$;
```

returned the value verbatim while the same column read as a pseudonym.

WHY IT STAYED HIDDEN

The demo checked the notice both ways — control that the value really is
reachable, then that the proxy withholds it — and checked the error next to it
in one direction only: `16e. a backend error still says what went wrong`. That
check asserted the behaviour that carried the leak.

Beside the code, a comment: Postgres "composes error messages from its own text
rather than from a row". `RAISE` accepts an expression for the message. Second
time in this project a comment asserting a case could not arise is what kept it
from being tested — the first was disclosure 6.

Meanwhile `session.rs` already said, twenty lines away, that "every free-text
diagnostic field can be SQL-controlled (`RAISE` accepts expressions for Message,
Detail, Hint and object names), so rebuild the message from constrained fields
plus fixed text." The code did not do that. Two comments, one right and one
wrong, and the wrong one was the one next to the branch.

TWO MORE, FOUND BY PULLING THE THREAD

`CONTEXT` reproduces the text of a statement PL/pgSQL ran, so a value
interpolated into dynamic SQL comes straight back inside it. `W` joins
`LEAKY_FIELDS`, next to `q`, which was already there for the same reason.

And `USING ERRCODE` takes an expression. A SQLSTATE is five characters of
`[0-9A-Z]`, so `upper(substr(email, 1, 5))` returns five characters of the value
per query — about five queries for an address, against the 313 the documented
`count(*)` predicate oracle needs. Faster than the inference routes this design
declares out of scope, so it is closed rather than documented.

The code is kept when the error has no `CONTEXT` and replaced when it has one:
`RAISE` only exists inside PL/pgSQL and a function frame always produces one,
while ordinary errors produce none. Measured on Postgres 17 rather than assumed.

THE GATE'S LARGEST SUITE COULD NOT FAIL

While fixing the above, a property test began failing and the gate reported
`ok  cargo test  489 tests`. The count was real. The verdict was not:

```bash
out=$(cargo test --workspace ... 2>&1
      cargo test -p pgmask --lib --features fuzzing ... 2>&1)
status=$?          # <- the SECOND command's status, only
```

`$?` after a command substitution holding two commands is the last one's. For as
long as that was written that way, the workspace run — every integration test in
`crates/proxy/tests/`, including the adversarial suite when Postgres is
available — could not fail the gate. Only the lib-only second run was reported.

Both statuses now. Poison-controlled by planting a failure in the workspace run:
combined status 101 where it was 0.

That is the fourth exit status lost to a pipeline or a substitution in a day —
three in throwaway harnesses, one baked into the gate.

A PROPERTY THAT WAS A PROXY FOR THE REAL ONE

The failing test asserted `scrubbed.len() <= original.len()` — "if it can grow
the message it is rewriting content rather than dropping fields". Replacing the
message with fixed text makes that false by design, and length was never what
mattered. Restated as **a value that came in must not come out**, with
distinctive tokens so a match cannot be coincidence.

Writing it caught a second thing: asserted unconditionally, it fails, because
`C` is forwarded when there is no `CONTEXT`. That is correct, and it rests on a
measured property of Postgres rather than anything the proxy enforces. The
property now says so and tests both branches.

WHAT IT COSTS

An error's message is always withheld now. `42P01` and `23505` still reach the
client, which is the machine-readable half and what every driver surfaces. An
application whose PL/pgSQL raises custom SQLSTATEs for business logic loses
them — over-withholding, in the direction that does not disclose, and visible to
whoever runs it.

Three demo checks asserted the old behaviour and now assert the new contract in
both directions. `assert_no_canary` looks for the whole token, so it would have
called the SQLSTATE channel clean; the test checks for a five-character prefix
as well.

## 0.1.39 — the mutation runs were a fifth of a run

`45 survivors` has been sitting in the safety assessment as a known quantity.
It was never the survivor list. Two runs died part-way and both printed their
four outcome counts — caught, missed, timeout, unviable — and nothing else, so
a run that attempted 293 of 493 mutants read exactly like a complete one. The
second died on a full disk at 102 of 494.

A partial mutation run is worse than no run. It reads as coverage.

`test-mutants.sh` now counts what it planned against what it attempted and
refuses to report anything if they differ. Verified against the crashed run
still on disk rather than a synthetic one: 102 of 494, exit 1.

Two supporting fixes, both causes rather than symptoms:

* A free-space precheck. cargo-mutants copies the whole tree into `$TMPDIR` and
  rebuilds in it per mutant; the copy reached 5.4 GB. The run needs 20 GB and
  now says so before starting the container instead of dying at mutant 102.
* Cleanup of that copy, which a crash leaves behind. The 5.4 GB orphan from the
  crash was itself part of why the disk was full.

WHAT THE HARNESS STILL DOES NOT LOOK AT

`protocol.rs` and `mask.rs` are not in the mutated file list. `LEAKY_FIELDS` is
in `protocol.rs` — the error-field scrubbing that stops a unique violation
echoing `Key (email)=(alice@example.com)` back to the client — and the masks
themselves are in `mask.rs`. Both decide what reaches the client. Recorded, not
yet fixed: adding them changes what a complete run costs, and no complete run
has finished yet.

## 0.1.38 — four relations that were never a plain table

Partitioned tables, inheritance, domain-typed columns and generated columns had
no fixture. Each breaks a different assumption the plan binding makes, and each
had been probed once by hand and written down as a gap rather than pinned.

They are in the canary schema now, carrying the same canary as everything else,
under two tests. One sweeps sixteen statements and insists nothing escapes. The
other records what each statement *does* — served or refused — because a sweep
where every query errors is also canary-free, and only the second test tells the
two apart.

TWO OF MY PREDICTIONS WERE WRONG

I expected a **domain** column to be refused: `is_text_family` has never heard
of an OID allocated at `CREATE DOMAIN` time, so I reasoned the masker would
reject the result set and the operator would be pushed toward marking the column
allowed to get their query back. It masks normally. Postgres reports the *base*
type OID in `RowDescription`, so the masker never sees the domain.

I also expected the partitioned parent to be the hazard, since a
`RowDescription` for a read through the parent carries the partition's table
OID. A read through the parent is masked by the parent's rule. Reading the
partition *by name* falls to default-deny — safe, and a utility cost the
operator can see.

Inheritance matches partitioning in both directions, including the child's row
arriving through the parent, masked. A cast off a domain column is refused for
losing provenance, which is the general rule and nothing to do with domains.

Nothing was found. That is the result, and it is worth having as a fixture
rather than as a memory of having once checked: four poison controls — allowing
the column on each parent, and allowing the generated column — fail both tests,
so the fixture is live rather than accidentally quiet.

## 0.1.37 — a checksum is what makes content discovery worth running

CONTENT DISCOVERY COULD NOT SEE A CARD NUMBER

`classify --sample` advertises itself as catching "a column called `notes` full
of email addresses". It could find three shapes, because discovery iterated the
name rules that happened to carry a confirmation validator — email, phone, IP.
A column of card numbers under a meaningless name matched **nothing**. Not a
wrong proposal: none. `looks_like_phone` stops at 15 digits and a 16-digit PAN
sailed past it; an IBAN has letters in it.

Three checksum-backed detectors close that: Luhn for cards, mod-97 for IBANs,
and the SSA's own allocation rules for US Social Security numbers. The checksum
is the point. A shape test matches about one string of digits in one, so it can
corroborate a name and little else; Luhn rejects nine in ten and mod-97 rejects
ninety-six in ninety-seven, which is specific enough to make a claim about a
column nobody named.

Verified against a fixture rather than only in unit tests: 60 rows each of
Luhn-valid PANs, SSNs, IBANs, ordinary prose, and — the load-bearing negative —
16-digit numbers with a deliberately wrong checksum. The first three are
proposed `null` and flagged for review; the last two stay silent. That last
column is the proof the detector is reading the checksum and not the length.

Discovery still proposes `null` whatever matched. Knowing values are payment
instruments does not say whether the column is a card, an IBAN or a bank
account, and those get different treatment.

TWO LISTS, WHICH IS THE THING THAT WENT WRONG

Name rules and content detectors are now separate lists, because they answer
different questions — "the column is called `ssn`, what mask?" versus "the
column is called `col_7`, what is in it?". Splitting them creates a way to drift,
so a test asserts every confirmation validator is also a detector, and another
asserts every detector's label is a type the rules know.

The precise checks are listed first so a US SSN reports as "national_id or
phone" rather than "phone". The first cut deduplicated those labels through a
`BTreeSet`, which sorts alphabetically and silently threw that ordering away —
caught by a poison control that reordered the list and changed nothing.

Discovery also issues one query per column now instead of one per detector,
which would have been six after this change. The values are still counted and
dropped inside the sampling function; the caller receives labels and rates.

TWELVE GUARDS, TWELVE POISON CONTROLS, TWO SURVIVORS

Deleting the length bound from the card check broke no test: the too-short and
too-long examples failed Luhn as well, so only the checksum was rejecting them.
Replaced with numbers that are Luhn-valid at 12, 13, 19 and 20 digits, which
pins both edges exactly.

Worse in the IBAN check — all four structural guards were unexercised, every
invalid example failing mod-97 too. Fixed by searching for strings that satisfy
mod-97 and violate exactly one rule each: `GB8212` folds to 1 in six characters.

Both are the same failure the vacuous soak was: an assertion that passes for a
reason other than the one it names.

A POSTGRES YEAR IS NOT FOUR DIGITS

`truncate_date`'s text path read `&text[0..4]`. Against Postgres 17,
`'10000-06-15'::date` masked with `date-year` came back as `1000-01-01` — a
well-formed date nine thousand years from the real one, with nothing for the
client to notice. `date` reaches `5874897-12-31` and Postgres renders every
digit.

Second defect on the same line of reasoning: the era suffix was appended after a
timezone slice that ran to the end of the string, so
`0044-03-15 10:00:00+00 BC` came back as `...+00 BC BC`.

Parsed by delimiter now, and wide years are **refused** rather than coarsened.
jiff's civil date stops at ±9999, so the binary path already fails on them;
letting text succeed would mean the same stored value masking differently
depending on which protocol the client used, which
`binary_date_truncation_agrees_with_the_text_path` exists to forbid. This is a
behaviour change: a masked date column holding a year above 9999 now errors in
text as it already did in binary.

Four of the five guards in the rewrite are load-bearing under poison control.
The fifth — scoping the timezone search to the time field instead of the old
`rfind(...).filter(|i| *i > 10)` — is not, because the year bound twenty lines
above makes the two equivalent, and the doc comment says so rather than
implying it fixes something reachable.

RUSTDOC WAS NEVER RUN

`[`referenced_relations`]` sat in `analysis.rs` pointing at a function nobody
ever wrote, and four usage lines rendered `<seed>` as an unclosed HTML tag. The
gate ran fmt, clippy, audit and seventeen suites, and none of them look at doc
links. It runs rustdoc with warnings fatal now.

Four other documentation corrections, all found by an earlier audit and none
made until now: `floor_within` still carried a paragraph describing the clamping
it stopped doing two releases ago; `LEAKY_FIELDS` claimed to drop fields "when
the message mentions anything we are masking" while the code drops them
unconditionally, which is the safer behaviour the doc talked a reader out of;
the `Scrub` doc listed seven of the ten placeholders it emits.

## 0.1.36 — a fuzzer for the state machine, and the shapes the grammar could not say

Two parallel efforts, both required to prove themselves by reverting a real fix
and finding it again.

THE GRAMMAR COULD NOT EXPRESS TWO OF SIX DISCLOSURES

Measured over 5,000 generated statements before this: `SELECT * FROM (…)`
appeared **0 times**, `ROLLUP`/`GROUPING SETS` **0 times**. The soak could have
run for a year without finding 0.1.31 or 0.1.18. Volume was never the binding
constraint; grammar was.

Now 1,747 star wrappers per 5,000 (622 doubly nested), and the grouping-set
spellings behind a `postgres` dialect argument so the cross-engine campaigns
stay portable — CockroachDB rejects all three outright. `reach` tracks both, so
losing them fails the run instead of going quiet.

Poison control: deleting the unwrap loop from `group_by_columns` takes the
campaign from 0 leaks to **2,880**, on 10 of 10 seeds. At a flat 30% wrap rate
one seed in ten found nothing, so the top-level wrap is weighted toward
statements that group. Executable rate held: 400/400 on Postgres, no new
CockroachDB errors.

A FUZZER FOR THE PROTOCOL STATE MACHINE

Every campaign here fuzzes SQL shapes; `described_sql` substituting an unrelated
statement's text was an interleaving bug. `cargo-fuzz` over `PlanState` finds it
in ~4 seconds from an empty corpus, minimises it to two operations, and reaches
100% region coverage of `plan_state.rs`. It independently rediscovered the
non-UTF-8 `ParseUndecodable` precondition nobody pointed it at, and a portal-side
variant of the same bug.

`libfuzzer-sys` and `arbitrary` live in a workspace-excluded crate; the proxy
gains an off-by-default `fuzzing = []` feature and nine `#[cfg]`-gated lines.
Nothing compiles into the binary.

The oracle sits *inside* the crate as a child module because it needs private
fields for ground truth — an external target would infer "is a Describe
outstanding" from the function under test and agree with any answer it gave.
Parse texts and simple-query texts are disjoint pools, so a substitution is
detectable in both directions.

THE REGRESSIONS WERE NOT RUNNING

The minimised sequences were reported as carried by `test-all.sh`. They were not:
the module is feature-gated and the gate runs plain `cargo test`, so it compiled
none of them and reported the same 183 lib tests before and after they were
added. The gate runs the feature now — 470 tests, and reverting `described_sql`
fails four of them.

Caught because the test count did not move when a patch that adds tests was
applied. The same signal that exposed the vacuous soak.

TWO MORE INSTRUMENT FIXES

The shared oracle could not read `900000137.00000000`: `parse::<i64>()` fails on
it, so the simple-query harness saw 420 leaks where the extended harness saw 540
on an identical corpus. Fifth instance of a value not reaching a detector.
Normalised in the oracle so both harnesses see it; a genuine two-row average is
still correctly ignored.

And this gate destroyed concurrent work. Its teardown is machine-global —
`pkill -f` matches every pgmask on the host, and the container names are fixed
strings any checkout uses — so the agent fuzzing in a separate worktree lost its
proxies and its `pgmask-fuzz` fixture mid-run, while its load made three of this
gate's suites report false failures. A worktree isolates files, not processes.
The gate refuses now, naming the offending PID.

## 0.1.35 — evidence that made the proposal worse

`classify` on a `phone bigint` column, which is an ordinary way to store one:

```
  without --sample   name suggests phone, but a `partial` mask cannot apply to
                     bigint — pick another          [[column]]   # NEEDS REVIEW
  with --sample 200  confirmed by sampled values    [[column]]
```

Sampling casts to text, reads 100% phone-shaped values, and overwrote both the
verdict and the note — so the emitted entry lost its review marker and the proxy
refuses that result set at runtime. Adding evidence produced a worse proposal,
and it removed the warning that `mask_fits` exists to raise.

Sampling confirms a *shape*; it cannot vouch for a *type*. Those were conflated.
`confidence_after_sampling` is a pure function now, testable without a database,
and the note is appended rather than replaced — the incompatibility is the more
actionable half.

Fourth `classify` defect today. Two of the four made the tooling actively
harmful rather than merely incomplete: one proposed `partial` for national IDs,
publishing their last four digits, and one told operators a rule protecting a
materialised view was dead.

A THIRD SUITE THAT FAILED UNDER LOAD

`test-tls.sh` reported 3 of 7 while two fuzzers were building, and 7 of 7 alone.
Two bare `sleep 2`s after starting a proxy, and a `kill -0` check that proves
the process exists rather than that it is bound — pgmask resolves the whole
catalog before binding, so those are seconds apart under load. It waits on the
listener now, verified at 7 of 7 under twelve CPU spinners.

That is three suites with the same defect: `verify.sh`, `test-versions.sh`, and
this one. All three produced false *failures*, never false passes, which is the
safe direction — but three separate diagnoses today went into confirming that a
red gate was actually green.

## 0.1.34 — the four spelling disclosures were one property all along

Every disclosure in the analysis layer has been the same query written
differently:

```
  0.1.16   SELECT id, sum(salary) FROM t GROUP BY id
  0.1.18   ... GROUP BY <an alias of id>
  0.1.18   ... GROUP BY ROLLUP(<an alias of id>)
  0.1.31   SELECT * FROM ( ... GROUP BY id )
```

Each was fixed by adding a literal string to a list, which only protects against
spellings someone thought of. Four rounds is enough to conclude the list is the
wrong shape.

The property needs no list: **a rewrite that does not change what a query
returns must not lose a grouped column.** `crates/proxy/tests/analysis_properties.rs`
generates the rewrites — star wrappers, nested wrappers, output aliases,
ordinals, `ROLLUP`, an alias inside a `ROLLUP` — and requires the reader's answer
for each to still cover the plain form's.

`proptest` was already a dependency, used for the `RowDescription` parser and the
masks. It had never been pointed at `analysis.rs`, which is where all six
disclosures were. No new crate: `shapegen` hand-rolls its RNG rather than take
`rand`, and that posture is worth keeping.

THE FIRST VERSION WAS DECORATION

It compared `analyze(plain)` against `analyze(rewritten)` and passed against
*three reverted disclosures*. The singleton-group decision is not made in
`analyze`: `session` combines the reader with the catalog's unique keys and
passes the verdict down as a `Relaxations` flag, so both spellings returned
`Releasable`, the comparison found no difference, and nothing tripped.

Re-aimed at `group_by_columns` — the function whose answer actually differed
between spellings — reverting the 0.1.31 wrapper fix and the 0.1.18 alias fix
both fail the property now.

Reverting the 0.1.17 ordinal fix does *not*, and that is correct: breaking
ordinal resolution makes the reader return unbounded, which refuses. A safety
property should not fire on over-refusal, and the precision regression is pinned
separately in the inference suite.

The only reason I know these work is that real fixes were reverted and failure
required. They passed before that check too.

## 0.1.33 — tooling that told operators to delete a working defence

`classify --check` reported this, against a live materialised view whose column
the proxy was masking correctly:

```
1 rule(s) match nothing in the database. The column was renamed or
dropped, and the rule is protecting nothing:
  t.mv_contacts.email
```

An operator following that advice removes masking from a materialised view — a
denormalised reporting matview being a classic place for a copy of a masked
column to live. The rule was live: the proxy resolves `relkind = ANY('{r,v,m,p,f}')`.
`classify` walked `information_schema`, which omits materialised views entirely
(they are not in the SQL standard) and reports foreign tables as `'FOREIGN'`.

The two components disagreed about what a relation *is*. `classify` walks
`pg_catalog` with the proxy's own `relkind` set now, so they agree by
construction. Verified in both directions: the matview is proposed, and the
correct rule is no longer condemned.

Third defect in `classify` today, all in the component the product boundary
rests on — *the catalog belongs to whoever deploys the proxy; we ship the
tooling* — and the one whose coverage was lowest in the repo at 47.6%.

THE SOAK COUNTED ROUNDS IT NEVER RAN

Worth recording in full, because it is the failure this whole file is about and
I wrote it. `soak.sh` exists to prove the oracle can fail before believing a
clean run. Underneath that guard, the loop added 2,000 statements per engine
whether or not the harness executed anything. When the release gate's
`pkill -f 'target/release/pgmask'` killed the soak's proxies mid-run, it went on
reporting **800,000 statements, 0 leaks** in under a minute, with `served` and
`refused` frozen at the last real values. The only thing that caught it was two
numbers not moving between progress lines.

Two guards now, each verified by causing the failure: a round with no `RESULT`
aborts, and a `RESULT` that served *and* refused nothing aborts — a well-formed
line reporting no verdicts is the same emptiness better dressed.

ALSO

`test-versions.sh` lost a version's readiness under gate load and scored its 23
assertions as failures — correct behaviour, budget too short for five Postgres
containers and ten proxies starting together. Two minutes now, not thirty
seconds. It never passed anything it had not run, which is the difference
between it and `verify.sh`.

The lineage backstop's doc claimed the name comparison "cannot be wrong in the
unsafe direction". True for an explicitly classified column; for an unclassified
one the check also requires the relation's name to appear. Not a leak — no
exploit constructed — but an overstated guarantee is how the `SELECT *` wrapper
survived a day of grouping work.

## 0.1.32 — a soak, and a round zero that has to fail

`scripts/soak.sh [hours]` runs a fresh 2,000-statement corpus every round for as
long as it is given, over both wire protocols, against Postgres 17 and
CockroachDB v25.4.14, with a running total in `/tmp/pgmask-soak.status`.

**Round zero unmasks the catalog and requires the campaign to leak.** If it does
not, the run aborts and reports nothing further. A clean round from a detector
that cannot see is indistinguishable from a proxy that does not leak, and this
codebase produced that exact false clean three times in one day — `int8`,
`numeric` and `timestamptz`, each dropped by a type ladder one layer below the
canaries. Measured on the first run: 817,016 leaks with masking removed.

It also aborts on a blind spot rather than counting it clean: a value in a type
the harness cannot decode stops the run and names the type.

On a leak it stops and keeps the corpus at `/tmp/soak-leak-<seed>.sql`, so the
finding is reproducible rather than a number in a log.

Two harness bugs found while smoke-testing it, both this session's recurring
shape. `mkcfg` rewrote the backend port but not `catalog_dsn`, so the
CockroachDB proxy died on Postgres credentials. And the CockroachDB fixture load
was silent, so an empty fixture would have soaked against nothing — it verifies
`fz.people` is populated before starting.

WHAT A CLEAN SOAK MEANS

That no masked value appeared in a result set, across the statements it ran, on
both protocols and both engines. Not that the proxy is safe against an
adversary: inference is out of scope by design and `test-inference.sh` measures
what remains. Not that untested rules are sound either — `reach` fails when a
release path has no generated statement behind it, and that is the check which
bounds this one.

## 0.1.31 — the guard read one statement while the analysis judged another

```sql
SELECT id, sum(annual_salary) FROM demo.customers GROUP BY id            -- refused
SELECT * FROM (SELECT id, sum(annual_salary) FROM demo.customers
               GROUP BY id) q                                            -- served
```

The second returned `1|43700` — the real salary — against the shipped demo
catalog. The 0.1.16 disclosure, restored in full by wrapping it, and present
through every gate run used to validate the five fixes after it.

`analyze_inspected` unwraps `SELECT * FROM (subselect)` and classifies the
*subquery's* target list, so the released aggregate can sit inside the subquery.
`group_by_columns` read the *outer* group clause, which is empty for a wrapper,
and reported "no grouping". Two halves of one guard, looking at two different
statements. It reads the grouping after unwrapping now.

The comment on that function argued the case could not arise:

> Only the top level is inspected, which is sufficient — an aggregate inside a
> subquery is not the released field; the outer field referencing it has no
> provenance and is judged on its own.

Already false when written: the unwrapping is forty lines away in the same
module. I wrote that justification, believed it, and tested eleven spellings of
the grouping without once wrapping any of them.

It was found by an audit hunting *confident comments* rather than bugs — the
generalisation of 0.1.30, where `classify`'s doc claimed a capability the code
did not have.

ALSO: `described_sql` substituted an unrelated statement's text

`.and_then(..).or_else(..)` collapsed "no Describe outstanding" and "a Describe
is outstanding whose SQL was never recorded" into one branch, so the second fell
back to the last simple query. `SELECT 1, 2` reads as two literals and would
release fields belonging to `SELECT upper(email), …`. Same failure class as the
pipelined-Describe fix in 0.1.8, on a path it did not cover. A pending Describe
carries no SQL when the statement could not be decoded — a non-UTF-8 client
encoding — while the backend accepted the Parse anyway.

Three comments asserted it already failed closed, including the one on the test
written to pin it. That test passed vacuously: `simple_sql` was `None` in its
fixture, so the fallback had nothing to substitute. Given a simple query first,
it fails against the old code.

## 0.1.30 — `--sample` could confirm a guess but never make one

`classify` proposes a catalog from column names and, with `--sample`, checks the
values. Its own module doc says why:

> With `--sample` it reads data, because a column called `notes` full of email
> addresses …

It could not do that. Sampling ran only for columns whose *name* had already
matched a rule:

```rust
let matched = rules.iter().find(|rule| rule.pattern.is_match(&lower))
```

so it could confirm or downgrade a name-based guess and never make one. A `text`
column named `plain_key` holding fifty thousand real addresses drew no proposal
and not even a review flag. Neither did `search_key`, nor `sort_hint` full of
phone prefixes.

WHY THIS IS WORSE THAN AN ORDINARY BUG

The product boundary is that the catalog belongs to whoever deploys the proxy,
and we ship the mechanism plus the tooling that proposes one. A proposal tool
that cannot find PII in a column with an unhelpful name leaves a hole the
operator has no way to see: `classify --check`, the drift gate, cannot flag a
column `classify` does not know exists. Under `unclassified = "allow"` that is a
live disclosure; under default-deny it is a column masked by luck rather than by
decision.

Sampling now runs for columns whose name says nothing, proposing on an 80%
content match — as `NeedsReview`, never `Clear`, because the name gave no
corroboration and this file already argues that silently masking on content
alone trains people to override the tool.

Found while testing a hypothesis that was wrong. Generated columns looked like
the sharp shape — a stored column with real provenance whose value derives from
a masked one — and they are not: default-deny nulls an undeclared one, and
`classify` proposes `type = "email"` for `email_lower` from its name. The
layered defences held exactly as designed. Testing *why* they held is what
surfaced this.

REGRESSION COVERAGE

`demo.customers.lookup_key` holds addresses under a name that announces nothing.
Plain, not generated: the derivation was never the problem, and a column
populated by application code is both likelier and the same shape — encoding the
wrong hypothesis in the fixture would have been quietly misleading.

Three assertions, each failing for a different reason: that the column is found
at all, that the proposed type is the one the values are, and that it is flagged
for a human rather than decided alone.

Adding it failed `classify --check` immediately, because the shipped catalog did
not declare the new column. That is the drift gate doing its job on the first
change that gave it something to catch.

## 0.1.29 — a suite whose answer depended on the machine

`verify.sh` reported 66 of 88 while a mutation pass was running, and 88 of 88 on
the same commit once the machine was quiet. Six proxy startups waited with a
bare `sleep 2`, and pgmask resolves the whole catalog against Postgres before it
binds — on a loaded machine that is not two seconds, so every assertion in the
block ran against a closed port.

`scripts/test-fuzz.sh` already waits for the listener and explains why. The fix
was never carried across, which is the same shape as the `exit 0` this project
diagnosed in one release path and left standing in the other.

Verified against the condition that caused it rather than by reading: 88 of 88
with twelve CPU spinners running.

THE FIRST FIX WAS WORSE THAN THE BUG

It probed with `SELECT 1` through the proxy. Assertion 13d asserts
`pgmask_fields_rescued_total 1` exactly, and the probe query was itself
analysed, rescued and counted — a readiness check that corrupted the
measurement it existed to make reliable. It is a bare TCP connect now.

Third distinct way an instrument gave a confident wrong answer today: a value
dropped before the detector (`int8`, `numeric`, `timestamptz`), an answer that
depended on machine load, and a probe that changed what it measured.

WHY A FLAKY SUITE IS NOT JUST NOISE

It failed 22 assertions under load. With different timing it could as easily
have passed ones it had not earned — a proxy that never came up looks identical
to one that answered correctly if nothing checks. That is the same failure as
every other instrument problem here: the answer turning on something other than
the property under test.

## 0.1.28 — seven predicates that only one suite was watching

`cargo mutants` replaced each of these function bodies with a constant and
`cargo test` stayed green:

| predicate | what the constant does |
|---|---|
| `aggregate_argument_is_grouped -> false` | reopens 0.1.19's summary-of-a-grouped-column disclosure |
| `statement_references_masked_column -> false` | disables the lineage backstop *and* the mask gate on fine `date_trunc` |
| `is_system_relation -> true` | every relation reads as `pg_catalog`, so the fast path serves user tables unmasked |
| `is_parseable -> true` | trusts input the parser rejected |
| lexer word test, `&&` to `\|\|` | the backstop under lineage, the catalog fast path and the grouping guard |
| lexer quoted-name handling | 0.1.8 fixed a porous version of exactly this |
| `pseudonym_key` floor, `<` to `<=` | 0.1.9's sixteen-byte minimum, its boundary never asserted |

All seven are pinned now, and each was verified by applying the mutation and
requiring the new test to fail — not by assuming it would.

WHAT THEY HAVE IN COMMON

Every one is covered end-to-end by the shell campaigns, and not at all by
`cargo test`. `cargo mutants` only runs cargo tests, so it found precisely the
set where the unit suite leans on a suite it cannot invoke.

That is a different failure from the rest of today. The instrument was not
blind — `test-fuzz.sh` would have caught most of these. But it is not the
instrument anyone runs before pushing, and `cargo test` would have stayed green
while `is_system_relation` returned `true` for every OID.

TWO MORE HARNESS MISTAKES ON THE WAY

`-- --test-threads=1` reaches *every* cargo invocation cargo-mutants makes,
including `cargo build`, which rejects a test-harness flag; the run died at the
baseline with a bare `Usage:` line and zero mutants tested. `RUST_TEST_THREADS`
is the right mechanism.

The container start was piped to `/dev/null`, so a failure surfaced only as
"postgres did not start" — the third diagnosis today slowed by a log sent to
nowhere, after the proxy log in the CockroachDB work and the dropped values in
the extended harness. It prints the error and the last lines of the Postgres log
now.

## 0.1.27 — mechanical mutation, and two measurements I got wrong first

Two things claimed in 0.1.26's notes and not delivered: real line coverage, and
mutation testing that is not a hand-picked list. Both are here, and both
produced a wrong answer before a right one.

COVERAGE

Measured with `PGMASK_ALLOW_SKIP=1`, `catalog.rs` reads 62.6% and looks like the
weakest module in the proxy. That is not its coverage; it is the coverage of the
tests that do not need a database. Run against a real Postgres with
`--test-threads=1`, as `scripts/test-integration.sh` does, it is **88.4%**.

| lineage | mask | metrics | plan_state | catalog | protocol | session |
|---|---|---|---|---|---|---|
| 98.2 | 94.5 | 93.8 | 92.3 | 88.4 | 86.4 | 80.7 |

`tls.rs` reads 5.8% and that is also an artefact: the TLS suite exercises the
proxy as a subprocess, which this instrumentation does not see.

MUTATION

`scripts/test-mutations.py` breaks twenty-six guards someone thought to protect
— the same blind spot as an inference suite that only knows the spellings it was
given. `cargo mutants` mutates every function it can reach: **352 mutants, 222
caught, 111 missed**.

The `catalog.rs` survivors are the coverage mistake again, from the other side:
run with `-- --lib`, its tests never ran. `scripts/test-mutants.sh` now sets up
the invocation that means something and says why.

Three survivors in `analysis.rs` were worth acting on:

- The `bare` check for context functions, `&&` to `||`. A real gap: inverted, a
  context function *with arguments* releases, and `CREATE FUNCTION
  public.now(text)` returning its argument is a shape an ordinary user can
  create. Pinned.
- The `COALESCE` rule, `==` to `!=`. A real gap: inverted, two unreadable
  arguments release together. Pinned.
- `unwrap_star_over_subquery`'s early return. **Equivalent**, not a gap — both
  conditions are re-enforced by slice patterns in the same function. Recorded on
  the function so it is not re-litigated, rather than pinned with a test that
  would assert a shape refused for other reasons.

A DEFECT IN CODE FROM EARLIER TODAY

Writing the second test surfaced one. `grouping_may_reference` treated an
integer literal *nested in an expression* as an ordinal into the target list, so
`GROUP BY coalesce(col, 0)` resolved `0` to nothing and reported the grouping
unbounded — refusing an honest aggregate — while `GROUP BY col + 1` resolved `1`
to the first target and pulled its columns in. Safe in both directions and wrong
in both. An integer is an ordinal only as a grouping *element*; descending into
an expression now clears that flag, as it already did for output aliases.

Fourteen more survivors are `grouping_may_reference` arms, all precision-only:
deleting one makes the grouping unbounded, which refuses. They are pinned by
asserting that every node type the function claims to read is read — the same
shape of test as the ordinal-resolution one in 0.1.19, and for the same reason.

Poison control re-run after the walker change: 0 leaks with the
summary-of-a-grouped-column rule, 1,740 without.

## 0.1.26 — was this rule ever consulted?

The leak oracle answers "did anything escape". No suite answered "was this rule
reached at all", and a release rule no generated statement can express is a rule
the campaign is silent about however many statements it runs. `PURE_SCALARS`
(0.1.9) and `date_trunc` (0.1.23) were each in that position when they leaked,
and both were found by reading code rather than by the campaign.

`crates/fuzz/src/bin/reach.rs` replays a corpus through `analysis` alone — no
server, no proxy — and fails when a tracked release shape is unreachable. In the
gate as "release paths reached". Verified both directions: 3,000 statements
reach all thirteen and exit 0; a 40-statement corpus reports `date_trunc`,
`size formatter`, `pure scalar` and `string_agg` unreachable and exits 1.

Two things the probe got wrong first, both worth recording because both would
have produced a confident, false number.

It passed `field_count = 1`, so `analyze` collapsed nearly everything to
`Unknown` on a positional mismatch and it claimed 99 of 3,000 statements were
releasable. It reads the real target-list length now.

After that fix the number was still 99, and the temptation was to report it as a
finding. It is not one: `Unknown` from the allowlist does not mean refused, it
means "a plain column projection, which provenance decides". The labels now say
"released by the allowlist alone" and "left to provenance or lineage", which is
what the counters measure. A misleading headline in a security suite is worth
about what a blind detector is.

## 0.1.25 — a value nobody could decode is not a value that did not leak

Three disclosures hid in one line of the extended harness, which returned
`None` both for "this column was NULL" and for "I could not decode this type".
The second is a blind spot; the first is nothing. Conflating them meant the
oracle reported clean on values it had never seen:

  0.1.19  `sum(int4)` is `int8`          hid the singleton-group disclosure
  0.1.21  `avg` is `numeric`             recorded as a comment and left
  0.1.24  `date_trunc` is `timestamptz`  broke that release's own poison control

Each fix added a type, and each time the next type was equally silent.
`interval`, `bytea`, `json`, arrays and CockroachDB's own types were all queued
up behind it.

An undecodable value is now an event with a name. `render` returns
`Value`/`Null`/`Undecodable`, the run tallies them by type from
`row.columns()[i].type_().name()`, prints them, and **fails**:

```
  UNDECODABLE, so never scanned:
     6884  date
Error: 6884 value(s) of type date could not be decoded, so no detector saw them
```

Verified the way the rest of this is: by deleting the `date` decoder and
requiring the failure. Before this change that same deletion reported
`leaks=0` and passed.

This is the fix that should have been made after the first instance rather than
the third. Adding a type closes one hole; making the hole audible closes the
class.

## 0.1.24 — generate the release paths, and make the control fail first

Every rule in `classify` that turns a refusal into an acceptance, and whether a
generated statement could reach it before this release:

| release path | reachable |
|---|---|
| literals, `count(*)`, reducing aggregates, ranking windows | yes |
| `SqlvalueFunction`, `CONTEXT_FUNCTIONS`, `SIZE_FUNCTIONS` | no |
| `date_trunc` | **no** — 0.1.23's disclosure |
| `PURE_SCALARS` | **no** — 0.1.9's disclosure |

Two of the three unreachable paths had each already cost a disclosure, both
found by reading code. The new arm emits them, and emits the *unsafe* spellings
alongside the safe ones — `date_trunc('day', …)` next to `'year'`,
`pg_size_pretty(<value>)` next to nothing at all. An arm that only produces the
releasable form asserts nothing, which is exactly what the grouped-aggregate arm
did for a full release while projecting `count(*)`.

THE CONTROL FAILED, WHICH IS WHY IT EXISTS

First run of the poison control — revert 0.1.23, require the campaign to find
it — reported **zero leaks**. The arm could not see the bug it was built for.
`date_trunc` returns `timestamptz`, and the harness type ladder decoded
`String`, integers, floats, bool, uuid, `civil::Date` and `Decimal`. The value
was discarded one layer below the detector.

That is the third instance of the same failure in this codebase:

  0.1.19  `sum(int4)` -> `int8` dropped        hid the singleton-group leak
  0.1.21  `avg` -> `numeric` dropped           recorded as a comment, not fixed
  0.1.24  `date_trunc` -> `timestamptz` dropped  broke this arm's own control

With `civil::DateTime` and `Timestamp` added: 1,550 leaks reverted, 0 with the
fix. The arm can now rediscover 0.1.23.

WHAT THE ARM DELIBERATELY DOES NOT EMIT

`version()`, `current_database()`, `pg_backend_pid()` and
`pg_size_pretty(pg_table_size(t))` were in the first cut and produced twelve
cross-engine mismatches — `20` vs `20.5` from integer versus decimal division,
and two version banners. None was a masking difference. This corpus is shared
with the differential, whose premise is that the same fixture and catalog give
the same masked output, and these are properties of the engine and the session.
None of them takes a column, so none can leak one; unit tests cover that path.
`round(sum(x)::numeric / …)` stays, with the cast that makes both engines agree.

`shapegen` runs 398 of 400 statements after all this, up from 378 — the arm
needed real date columns rather than whatever `typed_col` returned, since
`date_trunc` over a uuid is an engine error and not a test.

## 0.1.23 — coarsening below the mask is not coarsening

`date_trunc` was released for any unit "at or above a day". The fixture's
`birth_date` is masked to its year, and through the proxy:

```
  plain birth_date                 1975-01-01   the mask
  date_trunc('day',  birth_date)   1975-02-14   the whole value
  date_trunc('week', birth_date)   1975-02-10   a seven-day window
```

The rule was written as "coarse enough to lose the day". Soundness needs "at
least as coarse as the mask", and this module cannot see the mask — the field is
computed, so it has no provenance and no classification.

Found by enumerating which release paths a generated statement can reach.
`date_trunc` was one of three that nothing in the corpus could produce, and two
of those three have now produced a disclosure — the other was `PURE_SCALARS` in
0.1.9.

TRIMMING THE LIST WAS TOO EXPENSIVE

Restricting the units to year and coarser also refused
`date_trunc('month', placed_at)` on a column the operator set to `mask = "none"`
— the demo catalog runs without lineage, so there was no second chance to
release it, and ordinary time bucketing broke.

Year and coarser are now released unconditionally, because year is the coarsest
date mask on offer and nothing finer can escape through it. Finer units are
released only when the statement names no masked column at all, which is the
same lexical backstop the lineage and catalog paths use. Both directions
measured: the three fine units refused over `birth_date`, and
`date_trunc('month', placed_at)` and the month-bucket-with-sum query still
served.

The pair of booleans threading through `classify` became a `Relaxations` struct
on the way through. This was the second flag, and the call sites had stopped
saying what `true, false` meant.

## 0.1.22 — count what executed, not what was generated

Measured on the fuzz fixture, sqlsmith runs **123 of every 400 statements**. The
other 277 are `anymultirange is not a multirange type`, `cannot determine
element type of "anyarray"`, `cannot cast type unknown to anyenum`, `operator
does not exist: point = point` — polymorphic catalog functions called with
ill-typed arguments. They exercise the type resolver, not the masker.
`shapegen` runs 397 of 400, and generates the thing that actually decides
masking: how many source columns can reach one output field.

So the shape corpus is appended to each seed of the main replay, not just to the
600-statement extended run it fed before. Appended, not substituted — sqlsmith
reaches operators and functions nobody here would think to write, which is its
whole value. Effect on one run:

| | before | after |
|---|---|---|
| served | 2,083 / 18,000 (12%) | 6,741 / 19,200 (35%) |
| Postgres errors | 73% | 37% |
| masked values reached | 26,153 | 21,557,391 |

`shapegen`'s own error rate fell from 5.5% to 0.75% along the way, and the cause
was one mistake made twice: the windowed-aggregate arm and the grouped-aggregate
arm both return `bigint`/`numeric` while declaring `typed: false` — the exact
flag introduced to stop a date being paired with text under a set operation. The
residue is `min(uuid)`/`max(uuid)`, which Postgres does not have; the shape does
not record which typed column it carries, and 3 in 400 does not justify the
refactor that would fix it.

The README claimed "24,000 statements, 96,000 executions" and counted
*generated*. It now reports the executed and served fractions, because that is
the number someone deciding whether to trust this would want.

## 0.1.21 — a value the harness cannot decode is a value the oracle never sees

0.1.19 restricted the generator to `sum` and said why in a comment: `avg` over
an integer returns `numeric`, the harness could not decode it, and an `avg`
disclosure would have been generated and then discarded before any detector
ran. That is a documented hole, not a closed one, and it is the same shape as
the defect that hid the singleton-group leak — `sum(int4)` is `int8`, and int8
was being dropped too.

`rust_decimal` was already a workspace dependency; the fuzz crate now enables
its `db-tokio-postgres` feature and renders `numeric` through the same type
ladder. `avg` is back in the generator: 60 `avg` disclosure shapes per 1500
statements.

Verified the way the rest of this is verified rather than by inspection: with
the guard removed the campaign reports 180 leaked salaries through `avg` alone,
and 0 with it restored. `avg` over a singleton group returns
`900000137.00000000`, so the values are normalised before the integer detector
sees them.

## 0.1.20 — the same product, on the other engine

CockroachDB resolves an output alias in a grouping exactly as Postgres does, so
the 0.1.18 disclosure existed there too and had never been exercised: the
generated grouping product ran on Postgres only. It runs on both now — 144 key
spellings refused, 0 leaked, 28 non-key served, 0 over-refused. `ROLLUP`, `CUBE`
and `GROUPING SETS` are unsupported on CockroachDB, so those 252 statements are
rejected by the server and stay Postgres-only.

Getting there took three diagnoses, and only the first was about the proxy.

The proxy resolves the whole catalog at startup and refuses to run when a
declared column is missing — "a half-loaded catalog has unknown coverage". The
CockroachDB stand-in carried four of the ten columns the demo catalog declares.
That is correct fail-closed behaviour, not a bug.

`demo.orders` and `demo.customer_directory` are not in that fixture either, so
their rules name columns that cannot exist; they are stripped, as
`test-cockroach.sh` already does.

The last one was a missing trailing newline. The strip regex ends its match on
`(?=\n\[\[|\Z)` and consumes whole `.*\n` lines, so when the rewritten catalog
was joined without a final newline the last `[[column]]` block could never reach
`\Z` and survived — exactly one declared-but-absent column, and the proxy
refused to start.

The reason that was found rather than guessed at: the suite had been sending the
proxy's stdout to `/dev/null`, so a precise startup error arrived as "proxy did
not come up". The log is kept now and printed on failure. Three rounds of
guessing bought one small change to the harness that would have answered it
immediately.

## 0.1.19 — the campaign could not have found it

A summary of a column the query *groups on* is that column. Within a group it is
constant, so `sum(x)/count(*)` is `x` exactly — every group, any data, no unique
key involved, which is why the key test added in 0.1.16 never fired:

```sql
SELECT annual_salary AS g0, sum(annual_salary) AS c0 FROM fz.people GROUP BY 1
```

Found by the generated poison campaign rather than by review, and only after
two independent reasons it could not have been found before.

WHY 176,000 STATEMENTS REPORTED CLEAN

The generator's only `GROUP BY` arm projected `count(*)`, which discloses
nothing whatever it is grouped by. No generated statement could reach a reducing
aggregate over a grouping at all — the shape was outside the grammar, so the
clean runs said nothing about it. That is the second time this generator has
been missing precisely the arm that mattered; the windowed-aggregate arm was
added in 0.1.5 for the same reason.

The extended harness then read values with `try_get::<Option<String>>` and
dropped every column it could not decode as text. `sum(int4)` returns `int8`, so
the numeric poison detector could never fire on that path — and neither could
the date or uuid ones. The 0.1.11 note that both harnesses now share
`fuzz::oracle` was true and insufficient: sharing detectors does not help if the
values never reach them, and that fix was verified with `ip-prefix`, which
happens to sit on a `text` column. Values are now rendered through a type ladder
before the oracle sees them.

With both fixed the poison control worked: 480 leaked values with the rule
removed, 0 with it.

TWO WRONG FIXES FIRST, BOTH CAUGHT BY MEASUREMENT

Refusing whenever a *masked* column is grouped closed the hole and refused every
grouped aggregate in the fixture — under a default-deny catalog almost every
column is masked, so that is `summaries = "refuse"` by another route. The
grouping suite's non-vacuity guard failed the run outright: nothing was served,
so refusal proved nothing.

Comparing only the aggregate's plain-column argument halved the leaks, 480 to
240. `GROUP BY coalesce(annual_salary, 0)` is an expression, so the comparison
was skipped.

What works is bounding *every column the grouping could reference*, where an
unrecognised node means "could be anything" and refuses. That inversion is what
makes walking an arbitrary expression sound here when the rest of this module
will not do it: the other walks prove a column is absent and are unsound the
moment they miss a node, while this one only has to avoid under-collecting.

THE LIBRARY IS THE UNSAFE OPTION HERE

`pg_query::ParseResult::nodes()` is a generated traversal and the obvious way to
avoid hand-rolling this. Measured against the same groupings, it silently finds
nothing under `ARRAY[...]`, `GROUPING SETS`, `OVER (PARTITION BY ...)` or
`xmlelement(...)` — four misses, each a release. The table is recorded on
`grouping_may_reference`.

It is still used, as an oracle rather than an implementation:
`library_traversal_finds_no_column_this_misses` asserts our walker never returns
a narrower column set than `nodes()` does, so a hole in ours fails the build.

The mutation run then reported `ordinal grouping unread` as SURVIVED, which was
correct and worth the entry. Since 0.1.17 the lexical backstop catches whatever
the reader cannot resolve, so breaking ordinal resolution is *safe* — it only
costs precision, and nothing asserted precision. The distinguishing query is
`SELECT city, sum(annual_salary) … WHERE id > 5 GROUP BY 1`: read, the grouping
is `city` and it is served; unread, the backstop scans the whole statement,
finds `id` in the filter, and refuses. It is now pinned, and the mutation is
caught. 24 mutations, 0 survived.

## 0.1.18 — a name in the clause is not the column being grouped on

0.1.17 read the `GROUP BY` and got the wrong answer for two spellings, both
disclosures, both confirmed against a live server rather than argued about:

```sql
SELECT id AS c, sum(annual_salary) FROM demo.customers GROUP BY c
SELECT id AS c, sum(annual_salary) FROM demo.customers GROUP BY ROLLUP(c)
```

Postgres resolves an output alias in a grouping element, so both group by `id`,
one row per group. The reader saw the literal name `c`, found it in no unique
key, and released every salary — the original 0.1.16 disclosure with two extra
characters.

A bare name in a grouping element is now resolved as an output alias as well as
a column, collecting both names. Which one Postgres picks is not decidable here
— it prefers an input column of that name and only then the alias, and knowing
whether the input column exists needs the relation's columns — so collecting
both over-refuses in the shadowed case and cannot under-refuse in either.

Where the resolution applies was measured, not assumed. `GROUP BY ROLLUP(c)`
resolves the alias, because a grouping set nests grouping elements;
`GROUP BY c+0` reports `column "c" does not exist`, because an expression is not
one. The first cut used "at the top of the item", which is the wrong axis and
left the `ROLLUP` spelling open.

THE PATTERN, WRITTEN DOWN

Three releases in, the recurring defect is one mistake: treating *a name
appearing in the `GROUP BY`* as *the column being grouped on*. SQL separates
those four ways, and each was found separately and late — ordinals and stars in
0.1.17, aliases here. Anyone extending this should start from the list rather
than from the parse tree:

| spelling | denotes | handled by |
|---|---|---|
| `GROUP BY col` | that column | read directly |
| `GROUP BY 1` | an output column by position | ordinal resolution, refused if any target is a star |
| `GROUP BY alias` | whatever the target computes | alias resolution, in grouping elements only |
| `GROUP BY expr` | not decidable here | the session's lexical backstop |

Four mutations now cover the reader — unreadable-releases, ordinal-unread,
alias-unresolved, alias-unresolved-inside-a-grouping-set — because every one of
these was a live disclosure and none of them was caught by an existing suite.

GENERATING THE SPELLINGS INSTEAD OF REMEMBERING THEM

The deeper problem is that `test-inference.sh` only proves the spellings someone
already thought of are refused, which is the guarantee that kept failing.
`scripts/test-grouping.py` crosses 22 expressions — 16 that are the primary key
under a different spelling, 6 on a non-key column — with 14 syntactic positions
and adversarial aliases, one of which shadows a real column so that Postgres
prefers the input column over the alias. It asks the server whether each
grouping is actually one row per group rather than trusting the list.

It would have caught all three releases' worth of defects: `alias`,
`alias-in-rollup`, `alias-in-cube`, `alias-in-sets`, `quoted-alias` and
`ordinal` are all positions in the cross product.

Result: **256 key spellings refused, 0 leaked; 66 non-key spellings served, 0
over-refused by this guard.** The 60 non-key refusals are the pre-existing
expression-target rule, and separating those out required a differential — is
the plainest spelling of the same query refused too? — because the first version
of the script attributed all 60 to the guard and made its cost look several
times larger than it is.

## 0.1.17 — the guard was blunter than the problem

0.1.16 refused any `GROUP BY` it could not reduce to column names, reasoning
that a grouping we cannot read is one we cannot clear. Sound, and blunt enough
to break the most ordinary analytics query there is:

```sql
SELECT date_trunc('month', placed_at), sum(order_total) FROM orders GROUP BY 1
```

`date_trunc` over a coarse literal unit is *deliberately* released — that rule
predates the guard — so this was served before 0.1.16 and refused after it. The
claim in that release that expression groupings "were already refused anyway"
was drawn from one probe of `upper(city)` and does not generalise.

Two changes. The reader now resolves a column reference, an ordinal into the
target list, and `ROLLUP`/`CUBE`/`GROUPING SETS` over either, unioning names
across every set — safe, because each set is a subset of the union. Reading
these *strengthens* the guard as much as it relaxes it: the attack is
expressible in all of them, and 0.1.16 caught them only by finding them
illegible.

What still cannot be read now falls back to the lexical backstop instead of to a
refusal. It asks the weaker question the scanner can answer soundly — does the
statement name every column of some unique key? A grouping can only reference a
column the text mentions, so a key the text never names is a key the grouping
cannot cover. `GROUP BY id::text`, `GROUP BY (id+0)` and `GROUP BY
upper(id::text)` all name `id` and are refused; the `date_trunc` query names no
key column and is served.

The residual cost is a key column named *elsewhere* in a statement with an
expression grouping — `WHERE id > 5 … GROUP BY date_trunc(…)` — since the lexer
cannot tell where a name is used. Narrow, and pinned in the inference suite
rather than left to be discovered.

THINGS THAT DID NOT WORK, RECORDED SO THEY ARE NOT RETRIED

Walking the expression to collect its columns is the obvious answer and is
unsound here for the reason this module already documents: missing one node type
in a traversal releases a value.

Deparsing the group clause and lexing *that* looked like the sound version of
the same idea. It is not usable: `deparse` on a synthetically constructed tree
aborts the process from C on an invalid enum discriminant — `TRAP: failed
Assert("false")`, not an `Err` — so a grouping we cannot read would become a
crash rather than a refusal.

An ordinal is also refused whenever any target is a star. A star expands to
however many columns its relation has, so positions after it shift by an unknown
amount and `GROUP BY 2` can name one column while `target_list[1]` holds
another; if the real one is a key and the reported one is not, that releases.
`positions_are_trustworthy` already refuses such statements, so this is
unreachable today — checked anyway, because depending on a neighbouring guard to
stay sound is how the misaligned-star disclosure got in.

A nested grouping construct stays unreadable for a different reason.
`ROLLUP(a, CUBE(b, c))` does not parse as a nested `GroupingSet` — the raw parse
tree is not the analysed tree, only the outermost construct is resolved, and the
inner `CUBE` arrives as an ordinary `FuncCall`. Reading it would mean matching on
a function name, and `cube` is a real function from a real extension.

Three mutations added: releasing on an unreadable grouping, losing ordinal
resolution, and dropping the lexical fallback. The second is the first mutation
here that fails when the proxy becomes *more* restrictive, which is the right
shape for a change whose entire risk is over-refusal.

## 0.1.16 — a summary of one row is that row

`SELECT sum(annual_salary) FROM demo.customers GROUP BY id` returned every
salary, exactly, in a single query. It is not a small-cell problem: with `id`
unique, *every* group is one row, so the aggregate relaxation — "a reducing
aggregate cannot return a stored value whatever is inside it" — is false for the
whole result set at once. 0.1.15 recorded it as an accepted limitation. It is
the one route on that list that is decidable without query-set accounting: the
grouping is in the statement and the uniqueness is in `pg_index`.

`StatementInspection::group_by_columns` reads the top-level `GROUP BY` down to
column names, the catalog snapshot loads unique keys from `pg_index` (excluding
partial indexes, whose uniqueness is conditional), and the session withholds the
summary relaxation when the grouping covers one. A grouping that cannot be
reduced to names — `GROUP BY 1`, `GROUPING SETS`, `GROUP BY lower(a)` — is also
withheld, because a grouping we cannot read is one we cannot clear.

Scoped so ordinary analytics is untouched, which is why it is done here rather
than by turning summaries off: an ungrouped `sum`, a `sum` grouped by a non-key
column, and `count(*)` grouped by anything are all served exactly as before.

`WHERE id = 1` reaches the same value and is still accepted. Whether a predicate
matches one row is a property of the data, not of the statement, so there is
nothing sound to decide at Describe time. What the guard buys is the difference
between one query for the whole column and one query per row — and the inference
suite now asserts both halves, so undoing either is a failure rather than a
quiet regression. It joins the gate for that reason.

## 0.1.15 — measure what a client can reconstruct, and stop overclaiming

The suite asked one question — does a masked value appear in the output? — and
answered it well. It is not the question a reader assumes it answers. An
adversarial client does not need the value to appear: a grouped aggregate, an
ungoverned filter with `count(*)` (313 queries to a full address, measured), an
error used as a one-bit channel, and `ORDER BY` on a masked column all
reconstruct without disclosing. `analysis.rs` claimed the bar was "you cannot
read an anonymised value"; against an adversary that is false, and it is the
kind of false that decides whether this goes in front of regulated data. Both it
and the README now say what is true. `scripts/test-inference.sh` pins the routes.

## 0.1.14 — a detector that cannot be read is not a detector

A 3000-statement corpus reported 8,221 leaks, all false. The numeric canary
flagged any integer in the `annual_salary` range, and `row_number()` walks
straight through it. Tightening to exact-sequence membership still left 60 — an
int4 salary is indistinguishable from an ordinal by value alone — so the fixture
moved to `900000000 + i * 137` instead, which no ordinal reaches under the
statement timeout. The opposite failure mode to the day's other fixes, and just
as disabling: a real escape would have been three lines inside the noise.

## 0.1.13 — would we find out if a fix were undone?

`scripts/test-mutations.py` breaks each guard on purpose and requires the
narrowest suite to fail: 16 caught, 0 survived, 0 stale. Not in `test-all.sh`,
because it edits source and a gate that can leave the tree modified is a worse
hazard than the coverage. Python rather than bash because the first version
split its Rust-source table on `|`, straight through `|t| t.strip_suffix(...)` —
the harness had the defect it exists to find.

## 0.1.12 — a plan outliving the snapshot it was decided against

Statement and portal plans deliberately outlive their result set; nothing tied
them to the catalog snapshot they were resolved against. A refresh re-resolves
names to OIDs, and `DROP TABLE; CREATE TABLE` recycles one — so a plan cached
across that boundary applies the previous mapping's classification, which is a
different column's mask. Every other DDL direction already failed closed.
`PlanState` now drops cached statement and portal plans when the catalog
generation changes, keeping only the in-flight plan whose rows are already being
served.

## 0.1.11 — ambiguous principals, a blind oracle, ornamental checks

A startup packet naming `user` twice is refused rather than guessed at: pgmask
took the first and PostgreSQL takes the last, so masking resolved one identity
while the backend authenticated another. The extended-protocol oracle carried a
private one-token canary list and could not see any type-aware mask — the same
blind spot that let the windowed-aggregate disclosure through, reintroduced on
the other protocol; both harnesses now share `fuzz::oracle`. Eight CockroachDB
refutes truncated to `head -1` while the leak is on row two, so they passed
regardless of what the proxy did. Plus README numbers that did not reconcile.

## 0.1.10 — the channels that carry values around the masking

Three backend messages carry free text a client can steer to a stored value, and
none produces a RowDescription — so no plan, no refusal, no masking. `RAISE
NOTICE '%', (SELECT email …)` prints the address while the same column read
through the proxy is a pseudonym. Notice primary messages and
NotificationResponse are withheld; ParameterStatus is forwarded only for
reportable GUCs whose values cannot carry row data, `application_name`
deliberately excluded. An *error's* message is kept — Postgres composes it from
its own text, and an opaque proxy is a much worse trade.

## 0.1.9 — the release allowlists

`pg_size_pretty`, `pg_size_bytes` and `pg_column_size` take a *value*, not a
relation: `pg_size_pretty(salary % 10000)` with `pg_size_pretty(salary / 10000)`
reconstructs any bigint exactly. Moved to `PURE_SCALARS`, released only when
every argument is. A star over a zero-column relation expands to none, so target
count could match field count while every later position was shifted — a star
now makes positional correspondence unprovable. Set-returning functions in
`FROM` are refused outside three argument-driven generators, because the SRFs
behind `pg_stat_activity` match no relation rule. In the catalog: `for_roles`
iterated a `HashSet` so equal-ranked masks resolved differently per connection;
duplicate rules for one column are refused (which found a real duplicate in
`catalog-gui.toml`); `pseudonym_key` must be at least 16 bytes.

## 0.1.8 — five defects from an independent audit

Three protocol-legal disclosures with no error and no `Close`: `Parse` replacing
a statement left the previous plan cached, a Describe answered with an error left
its FIFO slot forever, and `described_sql` was a scalar while Describes are a
queue. Each Describe now carries its frontend Sync epoch — clearing on
`ReadyForQuery` is wrong under pipelining and ate live slots. Two masks failed
open (`range` with both bounds past the length, `outer` with `keep = 0`), and
`unclassified_mask` — the entire content of default-deny — was never validated,
so it returned undeclared columns verbatim while logging `unclassified=Mask`.
0.1.6's lexical backstop also missed quoted and keyword-shaped identifiers.

## 0.1.7 — the same gap, in the other release path

Having built a tool for the walker gap, the obvious next question was where else
a *release* decision depends on a tree walk. There are three: the analysis
allowlist, lineage (backstopped in 0.1.6), and `system_catalogs = "allow"`.

The third had never been fuzzed — nothing generates catalog queries — and it has
the largest blast radius, because it serves an entire result set unmasked.

**It has the same gap.** This is judged metadata-only while reading a user
table:

```sql
SELECT relname, count(*) OVER (PARTITION BY (SELECT email FROM demo.customers LIMIT 1))
  FROM pg_catalog.pg_class;
```

Not a value disclosure as it stands. The fast path ANDs the text check with an
engine-authoritative OID check, and a window clause influences ordering and
partitioning rather than what is projected — so the values that come back are
still `pg_class`'s. But the OID check only inspects fields that *have*
provenance, which leaves the text check standing alone for computed ones, and
the text check walks a tree with a known hole.

Fixed with the same lexical check as the lineage backstop: a statement naming a
known user relation as an *identifier* does not get the fast path. GUI clients
are unaffected, and for a pleasing reason — psql's introspection passes table
names as string literals, not identifiers, so `\d demo.customers` and `\dt`
still work.

## 0.1.6 — stop adding guards shaped like the last bug

No new disclosure. This closes the *class* that produced three of the five.

Lineage inverts the safety property: everywhere else a shape pgmask fails to
recognise is a shape it refuses, but here a source column the resolver fails to
notice becomes "nothing masked found, release it". Three disclosures came from
exactly that — a set operation, a view whose definition contained one, and a
scalar subquery `sqllineage` does not descend into — and each was closed with a
guard aimed at that construct. Guards aimed at constructs only ever cover the
constructs someone thought of, and the third arrived after the first two were
fixed.

**Guard 6 does not ask about constructs.** It asks whether a masked column's
name appears in the statement at all. If none does, no output field can carry a
masked value however the expressions nest and whatever the resolver resolved.
The resolver and the backstop must both agree before anything is released, and
they fail independently.

Two design choices worth stating:

- **Lexical, not syntactic.** The first implementation walked `pg_query`'s parse
  tree for column references. The new containment test caught it missing `id` in
  `sum(n) OVER (ORDER BY id …)` — the walker does not enter a `WindowDef`, which
  is the traversal gap `analysis.rs` has warned about since it was written. A
  backstop with a blind spot is not a backstop, so it now reads the **token
  stream**, where every identifier in the text is present by construction.
- **No name resolution.** An earlier version matched each name against the
  relations the statement mentions, which made it depend on the tree walk
  finding every `RangeVar` — the same completeness assumption that had already
  failed twice. Comparing bare names against every masked column in the catalog
  needs no traversal to be complete.
- Applied as a **downgrade of `Release`**, not an early return, so a field the
  resolver correctly identified as `Blocked` still names the column it derives
  from. An early return threw that message away.

Guard 5 (the scalar-subquery check from 0.1.5) is **removed** — the backstop
subsumes it and is not construct-shaped, and keeping both would be exactly the
accumulation this release is about. `SELECT upper(city) FROM t WHERE x IN
(SELECT …)` releases again as a result.

### The premise is tested, not assumed

`tests/lineage_superset.rs` asserts that every source column `sqllineage`
reports is one the backstop saw, across every construct the generator emits plus
the three that leaked. 37 comparisons, no violations. `SELECT *` is skipped and
documented: there the resolver names columns absent from the text and is the
complete side of the pair.

Verified to be able to fail: crippling the backstop makes it report 4
violations.

### Cost

Measured on a 1000-statement generated corpus: `lineage = "refuse"` serves 245,
`lineage = "allow"` serves 348. Unchanged by the backstop — the utility lineage
adds survives it. Over-refusal is real in principle (a masked `city` in one
relation blocks an expression over a released `city` in another) and did not
bite on this corpus.

**Lineage remains opt-in and off by default.** No amount of guarding changes
that it inverts the safety property; this makes the inversion survivable, not
sound.

## 0.1.5 — a windowed aggregate is not a summary

**Fixes the most serious disclosure so far.** It needs no unusual
configuration, no view, and no second engine:

```sql
SELECT sum(annual_salary)
         OVER (ORDER BY id ROWS BETWEEN CURRENT ROW AND CURRENT ROW)
  FROM fz.people;
```

returned **exact salaries** through a `numeric-bucket` column — 41248, 41385,
41522, where the plain column reads 25000. Under the *strictest* settings,
`lineage = "refuse"` and `opaque = "reject"`, because a `Releasable` verdict
short-circuits both.

`sum` is on the reducing-aggregate allowlist: it cannot return a value it
consumed, so what is inside it does not matter. That reasoning is sound for an
aggregate and false for a window function, where **the caller chooses the
frame** and a frame of one row makes every reducing aggregate the identity.
`count(*)` in the arm above already tested `over`; this arm did not.

This is not the group-of-one trade the module header accepts. A group of one is
incidental to the data; a frame of one is a thing the client writes down.

Every windowed aggregate is now refused — analysing frames to find the safe ones
is exactly the prove-absence reasoning the module refuses to do. `count(*) OVER
(…)` is deliberately still released: a frame changes which rows it counts, never
that it returns a count. Two existing tests asserted the vulnerable behaviour and
have been corrected.

### And a fifth: lineage released on a partial source set

The same campaign run also leaked a raw `date`, by a different route. Reduced:

```sql
SELECT min((SELECT d FROM fz.t8 LIMIT 1 OFFSET 3)) OVER (PARTITION BY subq.c0)
  FROM (SELECT id AS c0 FROM fz.v_join) subq
```

`sqllineage` does not descend into a `SubLink`, so the only source it reported
was `fz.v_join.id` — released. Lineage released the field on that basis, and the
value came from `fz.t8.d`, which is masked and which appears nowhere in the
sources it enumerated.

This is the third bug of one shape: **lineage releasing on an incomplete source
set** (after the set-operation view, and the view column released by rule).
`resolve` now refuses any statement containing a scalar subquery (guard 6). The
check is statement-level on purpose — locating which output field owns a given
`SubLink` means reproducing the target-list correspondence built elsewhere, and
getting *that* wrong is a leak. It costs lineage on `WHERE id IN (SELECT …)`,
which is utility, not safety. `upper(city)` still resolves and releases.

### How it was found, and what that says

The generated campaign found it, not review — and only by accident. The
statement that surfaced it reached a *date* column as well as a salary, and the
harness had a date detector and **no numeric one**. A campaign that reached only
salaries would have reported clean.

- The harness gains bucket detectors for `annual_salary` and `salary_big`.
- `shapegen` gains a windowed-aggregate arm; it had none, so no generated shape
  could reach this. Verified by reverting the fix: the corpus now reports 62
  leaks, correctly attributed, and 0 with the fix.

### The cross-engine differential

Every other oracle here needs someone to have predicted the bug: the canary
oracle needs a token planted in the right column, the shape matrix needs the
shape to have been thought of. `shapegen` closed one gap and opened another —
it explores what its author imagined, so its blind spots are his.

`scripts/test-differential.sh` needs no prediction. Both engines hold
byte-identical fixture data, and **masking is a property of the data and the
catalog, not of the engine**, so for any statement both proxies serve the masked
output must match. A difference is a defect by construction.

It matters most for pseudonyms: they are deterministic so a Postgres copy and a
CockroachDB cluster of the same data stay joinable. Until now that property was
asserted on one row in one suite; it is now checked across 157 served statements
of a generated corpus, and the run verifies the two fixtures really are
identical before comparing rather than assuming one file produced the same rows.

Result: 157 compared, 0 value mismatches, 84 decision mismatches — all in the
direction of CockroachDB refusing what Postgres serves, which is what
distrusting its provenance is supposed to look like. The control, a deliberately
skewed catalog, produces 141 mismatches, so the comparison can fail.

### Coverage said where the generator was not looking

Measured against the decision modules, a 2000-statement generated corpus reached
**19.6% of `mask.rs`**. The cause was one line of the generator: its column pool
was text and small integers, so no generated shape ever selected a `date`,
`uuid`, `inet` or `int8`. `date-year`, `ip-prefix`, uuid pseudonyms and 64-bit
bucketing had unit tests and fixed end-to-end checks, but no *shape* variety at
all — and shape variety is where all three leaks so far have lived.

Widening the pool took `mask.rs` from 19.6% to **33.1%** under the same corpus.
Projecting typed columns naively also put 230 engine errors into a corpus that
had been running at zero (a `date` in a `UNION` against text, `string_agg` over
a date), so the generator now tracks whether its projected column may be
non-text and keeps set operations and `string_agg` on text. Errors: 19 of 2000.

The lesson worth keeping: *"the fuzzer found nothing"* and *"the fuzzer never
executed that code"* look identical from the outside. Coverage is what tells
them apart, and it should be measured against the generated corpus alone rather
than the whole suite, which hides the gap behind unit tests.

## 0.1.4 — the other protocol, and the other integer width

No disclosure this time. Two coverage holes, both found by pointing existing
suites at the second engine.

### The extended protocol was one twelfth tested

Every end-to-end suite except `binary` speaks simple query. That is one protocol
of two, and **the two do not agree** — CockroachDB reports the first branch's
provenance for a set operation on the simple-query path and zero for the same
statement under `Describe`. A disagreement between protocols is what the first
disclosure here was made of, so testing one of them was testing half.

New `extended` binary replays a generated corpus through Parse/Bind/Execute with
binary results and the same canary oracle, with the same non-vacuity and poison
controls. It runs on both engines: Postgres serves 179 of 600 shapes and
CockroachDB 141, zero leaks on either, and both poison controls fire.

### int8 had no end-to-end coverage at all

`mask.rs` has handled int8 since it was written and a unit test covers it, but
no suite had ever produced one: Postgres's `int` is int4, so the fixture only
ever made four-byte integers. CockroachDB's `int` is int8, which surfaced this
as a driver deserialisation failure rather than a masking failure.

- Every integer width in the fuzz fixture is now explicit, so the same file
  produces the same column types on both engines.
- New `fz.people.salary_big int8` under `numeric-bucket`, asserted in the binary
  suite. `binary` is now 12 checks and runs on CockroachDB too, where all of
  them pass — including the pseudonym matching Postgres's byte for byte.

## 0.1.3 — fuzzing CockroachDB, and a third leak

**Fixes a disclosure reachable under `lineage = "allow"` on both engines.**
0.1.2 distrusted provenance for statements touching a set-operation view, which
sends those fields down the opaque path — where lineage decides them. Lineage
had not been told:

```sql
SELECT c0, row_number() OVER (ORDER BY c0) AS c1
  FROM (SELECT c0, count(*) AS c1
          FROM (SELECT r5.v AS c0 FROM fz.v_mixed r5) q5
         GROUP BY c0) q5
```

It resolved the expression to `fz.v_mixed.v`, found the catalog's `mask =
"none"` rule, and released what the provenance check had just refused to.
`resolve` now refuses any source column belonging to a set-operation view
(guard 5), pinned by a unit test that fails when the guard is removed.

A safety property established in one decision path is not established in the
others. The two paths here were written months apart.

### CockroachDB is now fuzzed

sqlsmith cannot read a CockroachDB schema (`Generating indexes...unknown
type:`), and generating against Postgres then replaying does not work either —
**395 of 400 statements errored**, because sqlsmith draws functions from the
target's catalog. A campaign erroring on 98.75% of its corpus is vacuous however
it reports; the poison control caught it.

New `shapegen` generates compositions of relational operators — subquery, CTE,
set operation, join, DISTINCT, window, value-returning aggregate, GROUP BY,
ORDER BY/LIMIT — in SQL both engines accept. Seeded xorshift, no new dependency.
On CockroachDB it produces **zero engine errors**, and it found the leak above
on its first run.

- New suite `scripts/test-fuzz-cockroach.sh`, wired into `test-all.sh`.
- `examples/fuzz/schema.sql` is now portable (no plpgsql `DO` blocks) and loads
  on both engines; roles moved to `examples/fuzz/roles.sql`, since neither
  `CREATE ROLE IF NOT EXISTS` nor `DO` is portable.
- The fuzz fixture gains `fz.v_mixed`, a union view mixing a released and a
  masked column, with the catalog deliberately releasing its output column. The
  existing `fz.v_union` was masked by an explicit `redact` rule, so the campaign
  had been generating queries against a union view for as long as the fixture
  existed without being able to catch the bug.
- **The role-bleed poison check accepted any non-zero exit.** When the roles
  fixture broke, 16 failed *connections* read as "violations detected" and the
  check reported the oracle as working. It now requires the poison run to have
  detected actual violations.
- **The campaign's poison control was too narrow to be reliable.** It unmasked
  two columns out of sixty and so depended on a random corpus happening to touch
  them. Adding one view to the fixture changed what sqlsmith generates for the
  fixed seed — it enumerates relations from the catalog — the new corpus missed
  both, and the control reported the oracle as broken on a run where nothing was
  wrong. It now also unmasks the twenty `redact` columns, which carry the canary
  token directly: 572 leaks detected where there had been 0. A control whose job
  is to prove detection works should not itself be a subtle test.

## 0.1.2 — set operations hidden in views

**Fixes a disclosure on Postgres as well as CockroachDB.** 0.1.1 decided
trustworthiness from the statement text, which cannot see this:

```sql
CREATE VIEW v_union AS SELECT city AS v FROM t UNION ALL SELECT email FROM t;
SELECT v FROM v_union;      -- no set operation in sight
```

Postgres reports provenance here naming `v_union.v` — the view's own column —
so it is one field with two source columns, and a rule releasing `v` releases
addresses along with cities. That is the rule an operator would write: `v` looks
like a city column, and `classify` sampling it sees cities. Run against the
0.1.1 binary with that rule present, the sweep leaks on **both** engines.

At catalog refresh the proxy now reads every view definition (`pg_get_viewdef`,
available on both engines), marks those containing a set operation, propagates
that to views built on them to a fixpoint, and distrusts provenance for any
statement referencing one. A definition that is null, empty or unparseable is
marked opaque: an engine that will not say what is in a view has not said the
view is safe.

Cost on Postgres is one shape moving from served-as-nulls to refused.

- New suite: `scripts/test-shapes.sh`, a canary sweep of 43 query shapes over
  the **simple-query** protocol against both engines, wired into `test-all.sh`.
  It asserts on values, not on reported provenance, and its catalog deliberately
  releases the union view's column so the trap is armed rather than covered by
  default-deny. `PGMASK_BIN` points it at another build — how the fix was shown
  to be load-bearing rather than merely present.
- The Phase 0 spike would **not** have caught either bug: it reads provenance
  via Parse + Describe, and CockroachDB reports zero there for a set operation.
  0.1.1 claimed otherwise; that claim was wrong. The spike gains the
  `view_union` shapes that established what Postgres reports.
- 229 cargo tests, up from 220.

## 0.1.1 — CockroachDB

**Fixes a disclosure.** CockroachDB reports the *first branch's* table OID and
attnum for a set operation's output field on the simple-query path, where
Postgres reports zero. Believing it applied one column's classification to
another column's values:

```sql
SELECT city FROM customers UNION ALL SELECT email FROM customers
```

returned real addresses in the clear. Five major Postgres versions of testing
never showed this, because Postgres declines to name an origin for a field that
has several.

The fix decides from the statement rather than from the engine: a parsed
statement containing a set operation — or one that will not parse, since that
cannot rule one out — has its provenance distrusted for every field, which are
then handled as computed fields already were. **Postgres behaviour is
unchanged**; the check only fires where Postgres had already zeroed provenance.
A `UNION` over released columns is still served under `lineage = "allow"` on
both engines.

- CockroachDB v25.4 is now a supported and tested engine, with a suite of 34
  assertions (`scripts/test-cockroach.sh`) wired into `test-all.sh`. It includes
  a direct-connection control proving CockroachDB really does report the
  leak-enabling provenance, so the suite cannot quietly stop testing anything.
- The lineage gate now asks whether a field *will be planned* without
  provenance, not whether the engine reported it as computed. Those are the same
  set on Postgres and are not on CockroachDB, where every set operation was
  being refused — safe, and needlessly worse than Postgres.
- New: [docs/engines.md](docs/engines.md).

## 0.1.0 — first release

MIT licensed.

A fail-closed column masking proxy for Postgres. Point a connection string at
pgmask instead of the database and sensitive column values are rewritten on the
way back out. Nothing else about how people work changes: same client, same SQL,
one different host and port.

**Status: usable for engineers working against a copy of production data. Not
yet something to put in front of production as a compliance control** — see
[what is not done](#what-is-not-done).

### How it decides what to mask

Postgres's `RowDescription` carries, per output field, the table OID and column
attnum it came from — and zero for both when the field is computed. That is
engine-authoritative provenance, free, with no SQL parsing.

The governing rule is that **the masking plan is bound to the `RowDescription`,
never to the statement.** Every row-producing path emits one first, so cursors,
`FETCH`, multi-statement queries and re-executed prepared statements are covered
without special handling. The only two paths that emit rows without one —
`COPY ... TO STDOUT` and the legacy `FunctionCall` message — are refused.

### What it does

- **Fourteen masks**: `none`, `null`, `redact`, `partial`, `inner`, `outer`,
  `range`, `hash`, `pseudonym`, `date-year`, `date-month`, `numeric-bucket`,
  `ip-prefix`, `scrub`. Dates and timestamps go through `postgres-types` with jiff, and
  `numeric` through `rust_decimal`, rather than epoch arithmetic of our own.
- **Deterministic pseudonyms**, so masked data stays joinable. Keyed by HMAC,
  domain-separated per semantic type so unrelated columns cannot be linked.
- **Per-principal policy.** The same column resolves differently by role, keyed
  on the username Postgres authenticated — never one a client merely claimed.
- **Default-deny.** A column with no rule is masked, so an incomplete catalog
  costs utility and never exposure.
- **Lineage** (`lineage = "allow"`, off by default): an expression is released
  when every base column it derives from is explicitly released. Cuts refusals
  on TPC-DS from 55% to 26%.
- **System catalogs** (`system_catalogs = "allow"`, off by default), so DBeaver,
  Harlequin, DataGrip and psql's `\d` work.
- **Structured logging** via `tracing`, and a Prometheus endpoint.
- **`classify`**, which reads a live schema and proposes a catalog, naming what
  it cannot decide rather than guessing. `classify --check` fails a build on
  catalog drift, including a column type change that would make a mask
  unapplicable — the one migration that otherwise surfaces as a production
  outage.
- **`scrub`**, which replaces identifiers inside free text with placeholders
  (`called <EMAIL>`) while leaving the sentence readable. Structured
  identifiers only, with checksums where one exists; it does not catch a
  person's name, and its limits are asserted as tests rather than described.
- **One command to verify everything**: `./scripts/test-all.sh`. A skipped
  suite counts as a failure.

### Verified

| suite | what it covers |
|---|---|
| 220 cargo tests | units, properties, adversarial wire client, differential vs `pgwire` |
| 82 demo assertions | end-to-end against a real Postgres, 50k rows |
| 115 version assertions | 23 checks x Postgres 13, 14, 15, 16, 17 |
| 7 TLS assertions | TLS on both legs through a real psql |
| 11 binary-format checks | every type-aware mask over the extended protocol |
| 21,600 role assertions | 24 concurrent sessions, 3 principals |
| 96,000 generated statements | sqlsmith x 4 policy configurations |

The generated-SQL campaign asserts that **no masked value ever reaches the
client** and refuses to pass on a technicality: a poison run with masking
removed must trip the oracle first, every query also runs against the database
so a run that never reached masked data reports as vacuous, the harness refusal
count is cross-checked against the proxy's own metrics, and one configuration
masks nothing so the proxy must be a byte-exact mirror.

Coverage across all suites is 79%, with the modules that decide masking highest:
`analysis.rs` 98%, `lineage.rs` 97%, `mask.rs` 94%, `session.rs` 85%.

### Hardening

`overflow-checks` is on in release, `unsafe_code` is forbidden, and `unwrap`
and `panic` are denied in the library and binaries. Clearing the resulting
lints found three reachable panics — a zero-length `Describe` frame, a
`numeric` at the decimal limit under `numeric-bucket`, and a UTF-8 boundary in
the test harness — each reproduced against the pre-fix code before being
fixed. A fourth, pre-existing, was found by a property test: bucket masking
clamped an out-of-range boundary and served a value that was not a bucket.

### What is not done

- **Nobody but Claude has reviewed this.** Everything above was written and
  assessed by the same author. The test suite is deliberately built so that
  finding nothing is hard to fake, but it is not a substitute for a reader.
- **It has never seen production traffic.** All measurement is TPC-DS, a
  synthetic fixture, and one read-only database branch. No soak test.
- **26% of TPC-DS is still refused**, even with lineage on. Row-level lookup
  work is comfortable; heavy analytical SQL is not.
- **Masked values do not round-trip.** Masking happens on the way out only;
  pasting a pseudonym back into a `WHERE` clause matches nothing. Join on the
  key inside one query, or filter by the real value. Making it round-trip needs
  inbound SQL rewriting and a reversible tokeniser, which is a different
  security posture, not a small change.
- **Changing the catalog needs a restart.** OIDs refresh on a timer; the file
  is read once at boot. No `SIGHUP` reload.
- **`min()`/`max()` over an explicitly released column are refused.** Correct in
  general, over-strict here, and unfixed.
- **DBeaver and DataGrip have not been driven** — only their query shapes and,
  for Beekeeper, its driver stack.
- **TLS is off in every shipped configuration.** The proxy warns at startup, and
  a masking proxy reachable in plaintext is not a boundary.

### The requirement that is not code

**A proxy is only a control if the database is not reachable around it.** Every
guarantee here assumes the backend's port is closed to the people the masking is
for. If someone can put the real host in their connection string, they get
unmasked data and pgmask never sees the query. Nothing in this process can
detect or prevent that. See the deployment section of the README.
