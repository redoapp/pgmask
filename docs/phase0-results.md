# Phase 0 provenance results

`PostgreSQL 17.10 (Debian 17.10-1.pgdg13+1) on aarch64-unknown-linux-gnu, compiled by gcc (Debian 14.2.0-19) 14.2.0, 64-bit`

| Shape | Group | Verdict | Via | Fields |
|---|---|---|---|---|
| baseline | baseline | PROVENANCE | describe | email=spike.t[table].2 |
| star | baseline | PROVENANCE | describe | id=spike.t[table].1 email=spike.t[table].2 name=spike.t[table].3 city=spike.t[table].4 |
| aliased | baseline | PROVENANCE | describe | contact_email=spike.t[table].2 |
| qualified | baseline | PROVENANCE | describe | email=spike.t[table].2 |
| join | baseline | PROVENANCE | describe | email=spike.t[table].2 note=spike.u[table].3 |
| distinct | baseline | PROVENANCE | describe | email=spike.t[table].2 |
| empty_result | baseline | PROVENANCE | describe | email=spike.t[table].2 |
| subquery_flat | subquery | PROVENANCE | describe | email=spike.t[table].2 |
| subquery_nonflat | subquery | PROVENANCE | describe | email=spike.t[table].2 |
| cte | subquery | PROVENANCE | describe | email=spike.t[table].2 |
| cte_materialized | subquery | PROVENANCE | describe | email=spike.t[table].2 |
| cte_recursive | subquery | OPAQUE | describe | id=<opaque> email=<opaque> |
| union_all | setop | OPAQUE | describe | email=<opaque> |
| union | setop | OPAQUE | describe | email=<opaque> |
| intersect | setop | OPAQUE | describe | email=<opaque> |
| except | setop | OPAQUE | describe | email=<opaque> |
| view | view | PROVENANCE | describe | email=spike.v_t[view].2 |
| view_star | view | PROVENANCE | describe | id=spike.v_t[view].1 email=spike.v_t[view].2 name=spike.v_t[view].3 city=spike.v_t[view].4 |
| view_nested | view | PROVENANCE | describe | email=spike.v_nested[view].2 |
| matview | view | PROVENANCE | describe | email=spike.mv_t[matview].2 |
| partition_parent | partition | PROVENANCE | describe | email=spike.p[partitioned].3 |
| partition_child | partition | PROVENANCE | describe | email=spike.p_west[table].3 |
| cast | expression | PROVENANCE | describe | email=spike.t[table].2 |
| lower | expression | OPAQUE | describe | lower=<opaque> |
| concat | expression | OPAQUE | describe | ?column?=<opaque> |
| coalesce | expression | OPAQUE | describe | coalesce=<opaque> |
| case | expression | OPAQUE | describe | case=<opaque> |
| window | expression | PARTIAL | describe | email=spike.t[table].2 row_number=<opaque> |
| group_by | expression | PARTIAL | describe | city=spike.t[table].4 count=<opaque> |
| aggregates | expression | OPAQUE | describe | count=<opaque> count=<opaque> string_agg=<opaque> |
| fn_setof_table | function | OPAQUE | describe | id=<opaque> email=<opaque> name=<opaque> city=<opaque> |
| fn_table_out | function | OPAQUE | describe | out_id=<opaque> out_email=<opaque> |
| fn_srf_target | function | PARTIAL | describe | email=spike.t[table].2 f_srf=<opaque> |
| lateral | lateral | PROVENANCE | describe | email=spike.t[table].2 note=spike.u[table].3 |
| temp_table | session | PROVENANCE | describe | email=pg_temp_4.tmp_t[table].2 |
| cursor | session | PROVENANCE | describe | email=spike.t[table].2 |
| extended_param | protocol | PROVENANCE | describe | email=spike.t[table].2 |
