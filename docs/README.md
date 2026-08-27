# Documentation

Use the shortest document that answers your question.

## Use and operate pgmask

- [README](../README.md): overview, quick start, configuration, and query behavior.
- [Security model](security.md): guarantees, threat postures, deployment controls,
  and known limits.
- [Operations](operations.md): schema changes, CI, restarts, logs, and metrics.
- [JSON and JSONB masking](json-masking.md): pointer policies, array wildcards,
  type placeholders, and how to inspect large documents.
- [Policy ownership](responsibilities.md): catalog review and team responsibilities.
- [GUI clients](gui-clients.md): DBeaver, DataGrip, pgAdmin, and `psql` metadata.
- [Engine notes](engines.md): PostgreSQL and CockroachDB differences.
- [Benchmarks](benchmarks.md): performance method and results.

## Audit and design evidence

These documents explain how decisions were reached. They are useful for review,
but they are not the shortest path to deployment.

- [Safety assessment](safety-assessment.md): chronological security audit and
  remaining verification gaps.
- [Build handoff](handoff.md): architecture, protocol state, and accepted design
  constraints.
- [Phase 0 results](phase0-results.md): provenance measurements.
- [MVP goal](mvp.md): original scope and acceptance criteria.
- [Phase 4](phase4.md): security-boundary hardening record.
- [Classification report](classification.md): catalog generator evaluation.
- [Lineage estimate](lineage-estimate.md): compatibility gain and risk analysis.
- [TPC-DS results](../examples/tpcds/README.md): analytical workload behavior.
- [Neon results](../examples/neon/README.md): live database validation.

Release changes are recorded in the [changelog](../CHANGELOG.md).
