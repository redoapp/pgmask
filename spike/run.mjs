#!/usr/bin/env node
/**
 * Phase 0 provenance spike.
 *
 * Answers the one question the whole masking-proxy design rests on: for each
 * query shape, does Postgres's RowDescription still identify the stored column
 * each output field came from?
 *
 * node-postgres exposes the RowDescription fields verbatim on `result.fields`:
 *   tableID  -> pg_class OID, or 0 when the field is not a plain column ref
 *   columnID -> pg_attribute attnum, or 0
 *
 * Usage:
 *   DATABASE_URL=postgres://... node spike/run.mjs [--md results.md]
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

import { shapes } from './shapes.mjs';

const here = dirname(fileURLToPath(import.meta.url));

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error('DATABASE_URL is required. See spike/README section in ../README.md');
  process.exit(2);
}

const mdIndex = process.argv.indexOf('--md');
const mdPath = mdIndex !== -1 ? process.argv[mdIndex + 1] : null;

/** Resolve pg_class OIDs to readable schema-qualified names + relkind. */
async function resolveOids(client, oids) {
  const wanted = [...oids].filter((oid) => oid !== 0);
  if (wanted.length === 0) return new Map();
  const { rows } = await client.query(
    `SELECT c.oid,
            n.nspname || '.' || c.relname AS name,
            c.relkind
       FROM pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE c.oid = ANY($1::oid[])`,
    [wanted],
  );
  return new Map(rows.map((r) => [Number(r.oid), { name: r.name, relkind: r.relkind }]));
}

const RELKIND = {
  r: 'table',
  v: 'view',
  m: 'matview',
  p: 'partitioned',
  f: 'foreign',
  t: 'toast',
  i: 'index',
  S: 'sequence',
  c: 'composite',
};

async function runShape(client, shape) {
  const record = { ...shape, fields: null, error: null };
  try {
    for (const stmt of shape.setup ?? []) await client.query(stmt);
    const result = shape.values
      ? await client.query({ text: shape.sql, values: shape.values })
      : await client.query(shape.sql);
    // Multi-statement simple queries yield an array of results.
    const first = Array.isArray(result) ? result[0] : result;
    record.fields = (first?.fields ?? []).map((f) => ({
      name: f.name,
      tableID: f.tableID,
      columnID: f.columnID,
      dataTypeID: f.dataTypeID,
      format: f.format,
    }));
  } catch (err) {
    record.error = err.message;
    // A failed shape can leave the session in an aborted transaction.
    try {
      await client.query('ROLLBACK');
    } catch {
      /* not in a transaction */
    }
  } finally {
    for (const stmt of shape.teardown ?? []) {
      try {
        await client.query(stmt);
      } catch {
        /* teardown is best effort */
      }
    }
  }
  return record;
}

/** A shape carries provenance if ANY field resolves to a stored column. */
function verdictFor(record) {
  if (record.error) return 'ERROR';
  if (!record.fields?.length) return 'NO FIELDS';
  const withProv = record.fields.filter((f) => f.tableID !== 0).length;
  if (withProv === 0) return 'OPAQUE';
  if (withProv === record.fields.length) return 'PROVENANCE';
  return 'PARTIAL';
}

function surprising(record, verdict) {
  if (record.expect === 'unknown') return false;
  if (record.expect === 'provenance') return verdict !== 'PROVENANCE';
  if (record.expect === 'opaque') return verdict !== 'OPAQUE';
  return false;
}

async function main() {
  const client = new pg.Client({ connectionString: DATABASE_URL });
  await client.connect();

  const { rows: [{ version }] } = await client.query('SELECT version()');
  console.log(`\n${version}\n`);

  console.log('Applying fixture...');
  await client.query(readFileSync(join(here, 'fixture.sql'), 'utf8'));
  await client.query('SET search_path TO spike, public');

  const records = [];
  for (const shape of shapes) {
    records.push(await runShape(client, shape));
    // The fixture DDL and any ROLLBACK above can reset search_path.
    await client.query('SET search_path TO spike, public');
  }

  const oids = new Set(records.flatMap((r) => (r.fields ?? []).map((f) => f.tableID)));
  const names = await resolveOids(client, oids);
  await client.end();

  // --- Console summary -----------------------------------------------------
  const pad = (s, n) => String(s).padEnd(n);
  console.log(`\n${pad('SHAPE', 22)}${pad('GROUP', 12)}${pad('VERDICT', 13)}DETAIL`);
  console.log('-'.repeat(100));

  const surprises = [];
  for (const r of records) {
    const verdict = verdictFor(r);
    const detail = r.error
      ? r.error.split('\n')[0]
      : (r.fields ?? [])
          .map((f) => {
            if (f.tableID === 0) return `${f.name}=<opaque>`;
            const meta = names.get(f.tableID);
            const kind = meta ? RELKIND[meta.relkind] ?? meta.relkind : '?';
            return `${f.name}=${meta?.name ?? f.tableID}[${kind}].${f.columnID}`;
          })
          .join(' ');
    const flag = surprising(r, verdict) ? ' <!>' : '';
    console.log(`${pad(r.id, 22)}${pad(r.group, 12)}${pad(verdict, 13)}${detail}${flag}`);
    if (surprising(r, verdict)) surprises.push({ r, verdict });
  }

  console.log('\n' + '='.repeat(100));
  const counts = records.reduce((acc, r) => {
    const v = verdictFor(r);
    acc[v] = (acc[v] ?? 0) + 1;
    return acc;
  }, {});
  console.log('Totals:', Object.entries(counts).map(([k, v]) => `${k}=${v}`).join('  '));

  if (surprises.length) {
    console.log(`\n${surprises.length} shape(s) differed from our prior:`);
    for (const { r, verdict } of surprises) {
      console.log(`  - ${r.id}: expected ${r.expect}, got ${verdict}`);
    }
  } else {
    console.log('\nNo surprises against our priors.');
  }

  // --- Decision inputs (handoff.md section 4) ------------------------------
  const byId = Object.fromEntries(records.map((r) => [r.id, r]));
  const viewField = byId.view?.fields?.[0];
  const viewMeta = viewField && names.get(viewField.tableID);
  const partField = byId.partition_parent?.fields?.[0];
  const partMeta = partField && names.get(partField.tableID);

  console.log('\nDecision inputs:');
  console.log(
    `  Views report ......... ${
      viewMeta ? `${viewMeta.name} (${RELKIND[viewMeta.relkind] ?? viewMeta.relkind})` : 'no provenance'
    }`,
  );
  console.log(
    `  Partition parent ..... ${
      partMeta ? `${partMeta.name} (${RELKIND[partMeta.relkind] ?? partMeta.relkind})` : 'no provenance'
    }`,
  );
  const subqueryOk = verdictFor(byId.subquery_nonflat ?? {}) === 'PROVENANCE';
  const cteOk = verdictFor(byId.cte ?? {}) === 'PROVENANCE';
  console.log(`  Non-flat subquery .... ${subqueryOk ? 'survives' : 'LOST'}`);
  console.log(`  CTE .................. ${cteOk ? 'survives' : 'LOST'}`);
  console.log(
    `\n  => ${
      subqueryOk && cteOk
        ? 'GO as designed.'
        : 'GO, but expect a higher rejection rate; re-read handoff.md section 4 decision rules.'
    }\n`,
  );

  if (mdPath) {
    const lines = [
      '# Phase 0 provenance results',
      '',
      `\`${version}\``,
      '',
      '| Shape | Group | Verdict | Fields |',
      '|---|---|---|---|',
      ...records.map((r) => {
        const verdict = verdictFor(r);
        const detail = r.error
          ? `error: ${r.error.split('\n')[0]}`
          : (r.fields ?? [])
              .map((f) => {
                if (f.tableID === 0) return `\`${f.name}\`=opaque`;
                const meta = names.get(f.tableID);
                return `\`${f.name}\`=${meta?.name ?? f.tableID}[${
                  meta ? RELKIND[meta.relkind] ?? meta.relkind : '?'
                }].${f.columnID}`;
              })
              .join('<br>');
        return `| ${r.id} | ${r.group} | ${verdict} | ${detail} |`;
      }),
    ];
    writeFileSync(mdPath, lines.join('\n') + '\n');
    console.log(`Wrote ${mdPath}`);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
