# Phase 0 provenance results

`PostgreSQL 17.10 (Debian 17.10-1.pgdg13+1) on aarch64-unknown-linux-gnu, compiled by gcc (Debian 14.2.0-19) 14.2.0, 64-bit`

| Shape | Group | Verdict | Fields |
|---|---|---|---|
| baseline | baseline | PROVENANCE | `email`=spike.t[table].2 |
| star | baseline | PROVENANCE | `id`=spike.t[table].1<br>`email`=spike.t[table].2<br>`name`=spike.t[table].3<br>`city`=spike.t[table].4 |
| aliased | baseline | PROVENANCE | `contact_email`=spike.t[table].2 |
| qualified | baseline | PROVENANCE | `email`=spike.t[table].2 |
| join | baseline | PROVENANCE | `email`=spike.t[table].2<br>`note`=spike.u[table].3 |
| distinct | baseline | PROVENANCE | `email`=spike.t[table].2 |
| empty_result | baseline | PROVENANCE | `email`=spike.t[table].2 |
| subquery_flat | subquery | PROVENANCE | `email`=spike.t[table].2 |
| subquery_nonflat | subquery | PROVENANCE | `email`=spike.t[table].2 |
| cte | subquery | PROVENANCE | `email`=spike.t[table].2 |
| cte_materialized | subquery | PROVENANCE | `email`=spike.t[table].2 |
| cte_recursive | subquery | OPAQUE | `id`=opaque<br>`email`=opaque |
| union_all | setop | OPAQUE | `email`=opaque |
| union | setop | OPAQUE | `email`=opaque |
| intersect | setop | OPAQUE | `email`=opaque |
| except | setop | OPAQUE | `email`=opaque |
| view | view | PROVENANCE | `email`=spike.v_t[view].2 |
| view_star | view | PROVENANCE | `id`=spike.v_t[view].1<br>`email`=spike.v_t[view].2<br>`name`=spike.v_t[view].3<br>`city`=spike.v_t[view].4 |
| view_nested | view | PROVENANCE | `email`=spike.v_nested[view].2 |
| matview | view | PROVENANCE | `email`=spike.mv_t[matview].2 |
| partition_parent | partition | PROVENANCE | `email`=spike.p[partitioned].3 |
| partition_child | partition | PROVENANCE | `email`=spike.p_west[table].3 |
| cast | expression | PROVENANCE | `email`=spike.t[table].2 |
| lower | expression | OPAQUE | `lower`=opaque |
| concat | expression | OPAQUE | `?column?`=opaque |
| coalesce | expression | OPAQUE | `coalesce`=opaque |
| case | expression | OPAQUE | `case`=opaque |
| window | expression | PARTIAL | `email`=spike.t[table].2<br>`row_number`=opaque |
| group_by | expression | PARTIAL | `city`=spike.t[table].4<br>`count`=opaque |
| aggregates | expression | OPAQUE | `count`=opaque<br>`count`=opaque<br>`string_agg`=opaque |
| fn_setof_table | function | OPAQUE | `id`=opaque<br>`email`=opaque<br>`name`=opaque<br>`city`=opaque |
| fn_table_out | function | OPAQUE | `out_id`=opaque<br>`out_email`=opaque |
| fn_srf_target | function | PARTIAL | `email`=spike.t[table].2<br>`f_srf`=opaque |
| lateral | lateral | PROVENANCE | `email`=spike.t[table].2<br>`note`=spike.u[table].3 |
| temp_table | session | PROVENANCE | `email`=pg_temp_1.tmp_t[table].2 |
| cursor | session | PROVENANCE | `email`=spike.t[table].2 |
| extended_param | protocol | PROVENANCE | `email`=spike.t[table].2 |
