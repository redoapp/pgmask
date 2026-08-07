#!/usr/bin/env python3
"""Run the query corpus through each pgmask policy and tally the outcomes.

Assumes three pgmask instances are already running against the same backend on
ports 6441/6442/6443 with the strict / rollout / permissive policies. See
README.md in this directory.

Reads the DSN from a file so no credential is written to the repo, and only ever
issues the SELECTs in queries.sql. The DSN is expected to carry
`options=-c default_transaction_read_only=on`, so the server refuses writes
itself rather than trusting this script.
"""
import os, re, subprocess, sys, pathlib

REPO = pathlib.Path.home() / "Developer/Work/pgmask"
DSN = (pathlib.Path.home() / ".pgmask/neon-ro.dsn").read_text().strip()
os.environ["PGPASSWORD"] = re.search(r"//[^:]+:([^@]+)@", DSN).group(1)

PORTS = {"strict": 6441, "rollout": 6442, "permissive": 6443}

queries = []
for line in (REPO / "examples/neon/queries.sql").read_text().splitlines():
    line = line.strip()
    if line and not line.startswith("--"):
        queries.append(line)

def run(port, sql):
    dsn = f"postgresql://neondb_owner@127.0.0.1:{port}/redo_internal?sslmode=disable"
    p = subprocess.run(["psql", dsn, "-tAq", "-c", sql],
                       capture_output=True, text=True, timeout=90)
    out = p.stdout + p.stderr
    if "pgmask:" in out:
        return "refused", out
    if "ERROR" in out:
        return "error", out
    return "served", out

print(f"{len(queries)} queries from examples/neon/queries.sql\n")
print(f"{'policy':<12}{'served':>8}{'refused':>9}{'other err':>11}")
print("-" * 40)

refusals = {}
for label, port in PORTS.items():
    tally = {"served": 0, "refused": 0, "error": 0}
    detail = []
    for sql in queries:
        try:
            kind, out = run(port, sql)
        except subprocess.TimeoutExpired:
            kind, out = "error", "timeout"
        tally[kind] += 1
        if kind == "refused":
            detail.append(sql)
    refusals[label] = detail
    print(f"{label:<12}{tally['served']:>8}{tally['refused']:>9}{tally['error']:>11}")

print("\nrefused under the rollout policy:")
for sql in refusals["rollout"]:
    print("  -", sql[:96])

print("\nserved under permissive but refused under rollout:")
only = set(refusals["rollout"]) - set(refusals["permissive"])
for sql in sorted(only):
    print("  -", sql[:96])
