#!/usr/bin/env python3
"""Every way to spell "group by the key", generated rather than remembered.

    ./scripts/test-grouping.py [--engine=postgres|cockroach] [--keep]

The singleton-group guard has now been wrong three times, and each time the
mistake was the same one: treating *a name appearing in the `GROUP BY`* as *the
column being grouped on*. SQL separates those at least four ways.

  0.1.16  refused anything it could not read, including `GROUP BY 1`
  0.1.17  read ordinals and grouping sets — missed output aliases entirely
  0.1.18  read aliases at the top of an item — missed `ROLLUP(alias)`

Every one was a live disclosure. None was caught by a suite; each was found by
hand, and then written into `test-inference.sh` as one more literal string. That
suite therefore proves only that the spellings someone already thought of are
refused, which is exactly the guarantee that kept failing.

This generates the spellings instead. It crosses expressions that are equivalent
to grouping by the primary key with every wrapper that can carry one, and
requires the proxy to refuse all of them. The same wrappers over a non-key
column must still be served, because a guard that refuses everything would pass
the first half trivially.

THE ORACLE

For a key spelling, "refused" is checked directly, and a served statement is
confirmed against the server before being called a leak: a grouping is singleton
when it produces as many groups as the table has rows, so `sum()` over it is the
row's own value. The confirmation matters — it distinguishes a real disclosure
from a generated statement that is merely odd.

Non-key spellings that come back refused are reported, not failed: over-refusal
is a cost, not a defect. But it is only attributed to *this* guard when the
plainest spelling of the same query is served — an expression in the target list
has no provenance and was refused long before any of this existed, and counting
those here would overstate the cost several times over. The first version of
this script did exactly that, reporting 60 over-refusals of which none were the
guard's.

Measured at 0.1.18: 256 key spellings refused, none leaked; 66 non-key spellings
served, none over-refused by the guard, 60 refused by the older rule.
"""

import os
import re
import subprocess
import sys
import time

PG_PORT = 55503
PROXY_PORT = 6543
CONTAINER = "pgmask-grouping"

# CockroachDB resolves an output alias in a grouping exactly as Postgres does,
# so the 0.1.18 disclosure existed there too. The fix is in the parser and is
# engine-independent, which is the sort of "should be fine" that produced the
# three bugs this file exists to prevent — so it is run against both. CRDB
# rejects `ROLLUP` and `GROUPING SETS` outright, and those spellings land in
# "rejected by the server" rather than needing to be special-cased.
ENGINES = {
    "postgres": {
        "image": "docker.io/library/postgres:17",
        "args": [],
        "env": ["-e", "POSTGRES_PASSWORD=demo", "-e", "POSTGRES_DB=demo"],
        "port": 5432,
        "dsn": "postgresql://postgres:demo@localhost:{port}/demo",
    },
    "cockroach": {
        "image": "docker.io/cockroachdb/cockroach:v25.4.14",
        "args": ["start-single-node", "--insecure"],
        "env": [],
        "port": 26257,
        "dsn": "postgresql://root@localhost:{port}/defaultdb?sslmode=disable",
    },
}
ROOT = subprocess.run(
    ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True
).stdout.strip()

GREEN, RED, YELLOW, DIM, OFF = (
    "\033[32m",
    "\033[31m",
    "\033[33m",
    "\033[2m",
    "\033[0m",
)

# Expressions that separate every row of demo.customers, because each is the
# primary key under a different spelling. Grouping by any of them makes every
# group a single row, so a released `sum()` is that row's salary.
KEY_EXPRS = [
    "id",
    "c.id",
    "(id)",
    "id + 0",
    "id * 1",
    "-id",
    "id::text",
    "id::bigint",
    "id::numeric",
    "abs(id)",
    "coalesce(id, 0)",
    "greatest(id, 0)",
    "upper(id::text)",
    "id::text || ''",
    "length(id::text) + id",
    "case when id > 0 then id else id end",
]

# Groupings on columns that are not declared unique. These must keep working.
SAFE_EXPRS = [
    "city",
    "c.city",
    "upper(city)",
    "left(city, 2)",
    "city || 'x'",
    "coalesce(city, 'none')",
]

# Every syntactic position a grouping expression can occupy. `{e}` is the
# expression; `{a}` is an alias bound to it in the target list.
#
# `ordinal` and `alias` need the expression in the target list, which changes
# the projection — that is the point, since both are resolved against it.
WRAPPERS = [
    ("direct", "SELECT sum(annual_salary) FROM demo.customers c GROUP BY {e}"),
    ("parens", "SELECT sum(annual_salary) FROM demo.customers c GROUP BY ({e})"),
    ("rollup", "SELECT sum(annual_salary) FROM demo.customers c GROUP BY ROLLUP({e})"),
    ("cube", "SELECT sum(annual_salary) FROM demo.customers c GROUP BY CUBE({e})"),
    (
        "grouping-sets",
        "SELECT sum(annual_salary) FROM demo.customers c GROUP BY GROUPING SETS (({e}))",
    ),
    (
        "sets-with-empty",
        "SELECT sum(annual_salary) FROM demo.customers c GROUP BY GROUPING SETS (({e}),())",
    ),
    (
        "ordinal",
        "SELECT {e}, sum(annual_salary) FROM demo.customers c GROUP BY 1",
    ),
    (
        "alias",
        "SELECT {e} AS {a}, sum(annual_salary) FROM demo.customers c GROUP BY {a}",
    ),
    (
        "quoted-alias",
        'SELECT {e} AS "{a}", sum(annual_salary) FROM demo.customers c GROUP BY "{a}"',
    ),
    (
        "alias-in-rollup",
        "SELECT {e} AS {a}, sum(annual_salary) FROM demo.customers c GROUP BY ROLLUP({a})",
    ),
    (
        "alias-in-cube",
        "SELECT {e} AS {a}, sum(annual_salary) FROM demo.customers c GROUP BY CUBE({a})",
    ),
    (
        "alias-in-sets",
        "SELECT {e} AS {a}, sum(annual_salary) FROM demo.customers c "
        "GROUP BY GROUPING SETS (({a}))",
    ),
    (
        "alias-and-ordinal",
        "SELECT {e} AS {a}, sum(annual_salary) FROM demo.customers c GROUP BY 1",
    ),
    (
        "extra-grouped-column",
        "SELECT {e}, sum(annual_salary) FROM demo.customers c GROUP BY {e}, city",
    ),
]

# Aliases chosen to be adversarial: one ordinary, and one that shadows a real
# column of the table — Postgres prefers the input column there, so the grouping
# is not what the alias suggests. A name needing quotes is exercised only by the
# quoted wrapper; unquoted, `AS Odd Name` is a syntax error and generating it
# just inflates the skip count.
ALIASES = ["g", "city"]
QUOTED_ALIASES = ["g", "city", "Odd Name"]

# The plainest spelling of the same query. If *it* is refused too, the refusal
# is not this guard's doing — an expression in the target list has no
# provenance and was refused long before any of this existed — so attributing
# it here would overstate the guard's cost.
PLAIN_NONPROJECTING = "SELECT sum(annual_salary) FROM demo.customers c GROUP BY {e}"
PLAIN_PROJECTING = "SELECT {e}, sum(annual_salary) FROM demo.customers c GROUP BY {e}"

# A composite key exercises the other half of the predicate — *every* column of
# some key must be grouped — which the cross product above cannot reach, because
# demo.customers has only the single-column `id`. Created here rather than in
# examples/demo/schema.sql so the other suites, which count their assertions,
# are unaffected.
COMPOSITE_DDL = """
CREATE TABLE IF NOT EXISTS demo.memberships (
    tenant int, email text, city text, amount int, UNIQUE (tenant, email));
INSERT INTO demo.memberships
SELECT i % 4, 'm' || i, 'city' || (i % 3), 100 + i FROM generate_series(1, 40) i;
"""

# (label, expect_refusal, statement)
COMPOSITE_CASES = [
    ("both key columns", True,
     "SELECT sum(amount) FROM demo.memberships GROUP BY tenant, email"),
    ("...in the other order", True,
     "SELECT sum(amount) FROM demo.memberships GROUP BY email, tenant"),
    ("...plus a third column", True,
     "SELECT sum(amount) FROM demo.memberships GROUP BY tenant, email, city"),
    ("...through aliases", True,
     "SELECT tenant AS a, email AS b, sum(amount) FROM demo.memberships GROUP BY a, b"),
    ("...through ordinals", True,
     "SELECT tenant, email, sum(amount) FROM demo.memberships GROUP BY 1, 2"),
    ("...through ROLLUP", True,
     "SELECT sum(amount) FROM demo.memberships GROUP BY ROLLUP(tenant, email)"),
    ("...through a parenthesised list", True,
     "SELECT sum(amount) FROM demo.memberships GROUP BY (tenant, email)"),
    # Half a composite key is not a key, and these are the queries a composite
    # key exists to make possible.
    ("one key column alone", False,
     "SELECT tenant, sum(amount) FROM demo.memberships GROUP BY tenant"),
    ("the other alone", False,
     "SELECT email, sum(amount) FROM demo.memberships GROUP BY email"),
    ("a non-key column", False,
     "SELECT city, sum(amount) FROM demo.memberships GROUP BY city"),
]

# Known cost of unioning names across grouping sets, asserted so it stays
# visible. Each set here is a single column and neither is a full key, so no
# group is singleton — but the union is {tenant, email}, which covers the key,
# and the guard refuses. Safe direction, real cost.
UNION_OVER_REFUSAL = (
    "SELECT sum(amount) FROM demo.memberships "
    "GROUP BY GROUPING SETS ((tenant),(email))"
)


def psql(dsn: str, sql: str) -> tuple[int, str]:
    out = subprocess.run(
        ["psql", "-w", dsn, "-X", "-tAq", "-c", sql],
        capture_output=True,
        text=True,
        env=dict(os.environ, PGPASSWORD="demo"),
    )
    return out.returncode, (out.stdout + out.stderr).strip()


def main() -> int:
    keep = "--keep" in sys.argv
    engine = "postgres"
    for arg in sys.argv[1:]:
        if arg.startswith("--engine="):
            engine = arg.split("=", 1)[1]
    if engine not in ENGINES:
        print(f"unknown engine {engine!r}; expected one of {', '.join(ENGINES)}")
        return 2
    spec = ENGINES[engine]
    container = f"{CONTAINER}-{engine}"
    direct = spec["dsn"].format(port=PG_PORT)
    proxied = spec["dsn"].format(port=PROXY_PORT)
    print(f"\nengine: {engine}")

    subprocess.run(["podman", "rm", "-f", "-v", container], capture_output=True)
    subprocess.run(
        ["podman", "run", "-d", "--name", container, *spec["env"],
         "-p", f"{PG_PORT}:{spec['port']}", spec["image"], *spec["args"]],
        capture_output=True,
    )
    for _ in range(90):
        if psql(direct, "select 1")[0] == 0:
            break
        time.sleep(1)
    if psql(direct, "select 1")[0] != 0:
        print("FAIL: postgres did not start")
        return 1
    if engine == "postgres":
        subprocess.run(
            ["psql", "-w", direct, "-q", "-v", "ON_ERROR_STOP=1", "-f",
             f"{ROOT}/examples/demo/schema.sql"],
            capture_output=True, env=dict(os.environ, PGPASSWORD="demo"),
        )
    else:
        # A portable stand-in: the demo fixture uses Postgres-only DDL. It must
        # carry *every* column the catalog declares for `demo.customers`, not
        # just the ones this suite reads — the proxy resolves the whole catalog
        # at startup and refuses to run when any declared column is missing
        # ("a half-loaded catalog has unknown coverage"). A subset schema made
        # it exit before binding, which read as "proxy did not come up".
        psql(direct, "CREATE SCHEMA IF NOT EXISTS demo")
        psql(direct, """
            CREATE TABLE IF NOT EXISTS demo.customers (
                id int PRIMARY KEY, email text, name text, phone text, city text,
                birth_date date, annual_salary int, last_ip text,
                account_uuid uuid, internal_note text);
            INSERT INTO demo.customers
            SELECT i, 'user' || i || '@example.com', 'Customer ' || i,
                   '555-' || lpad(i::text, 4, '0'), 'city' || (i % 4),
                   date '1975-02-03' + i, 40000 + i * 137,
                   '198.51.100.' || (i % 250 + 1),
                   ('00000000-0000-4000-8000-' || lpad(i::text, 12, '0'))::uuid,
                   'note ' || i
            FROM generate_series(1, 60) i;
        """)

    # Before the proxy starts, deliberately. Creating it afterwards put the new
    # key outside the catalog snapshot, and the first cases ran before the
    # refresh picked it up while later ones ran after — four spurious failures
    # that split exactly on the refresh boundary. The window that exposes is
    # real and is recorded in the README; it is not what this section tests.
    if engine == "postgres":
        psql(direct, COMPOSITE_DDL)

    config = "/tmp/pgmask-grouping.toml"
    base = open(f"{ROOT}/examples/demo/catalog.toml").read().splitlines()
    rewritten = []
    for line in base:
        if line.startswith("listen ="):
            rewritten.append(f'listen = "127.0.0.1:{PROXY_PORT}"')
        elif line.startswith("backend ="):
            rewritten.append(f'backend = "127.0.0.1:{PG_PORT}"')
        elif line.startswith("catalog_dsn ="):
            rewritten.append(f'catalog_dsn = "{direct}"')
        elif line.startswith("metrics_listen"):
            continue
        else:
            rewritten.append(line)
    # Trailing newline preserved deliberately: the strip below ends its match
    # on `(?=\n\[\[|\Z)` and consumes whole `.*\n` lines, so a file whose last
    # line has no newline can never reach `\Z` and the final `[[column]]` block
    # survives. That left exactly one declared-but-absent column and the proxy
    # refused to start.
    catalog = "\n".join(rewritten) + "\n"
    if engine != "postgres":
        # Same reason as the stand-in schema above, from the other side: the
        # CockroachDB fixture has no `demo.orders` or `demo.customer_directory`,
        # so their rules would name columns that do not exist and the proxy
        # would refuse to start. `test-cockroach.sh` strips them the same way.
        catalog = re.sub(
            r'\n\[\[column\]\]\nrelation = "demo\.(customer_directory|orders)"\n(?:.*\n)*?(?=\n\[\[|\Z)',
            "\n",
            catalog,
        )
    open(config, "w").write(catalog)

    # Kept, not discarded. The proxy resolves the whole catalog at startup and
    # exits when a declared column is missing, and with the log on /dev/null
    # that failure reads only as "did not come up".
    log_path = f"/tmp/pgmask-grouping-{engine}.log"
    with open(log_path, "w") as log:
        proxy = subprocess.Popen(
            [f"{ROOT}/target/release/pgmask", config],
            stdout=log,
            stderr=subprocess.STDOUT,
        )
    time.sleep(4)
    if psql(proxied, "select 1")[0] != 0:
        print(f"FAIL: proxy did not come up — {log_path}")
        print(open(log_path).read()[-1200:])
        proxy.kill()
        return 1

    rows = int(psql(direct, "SELECT count(*) FROM demo.customers")[1])

    def is_singleton(sql: str) -> bool:
        """Does this statement return one row per table row?

        Asked of the whole statement, not of the expression, because the two
        can differ. `SELECT id AS city, … GROUP BY city` groups by the *input*
        column `city` — Postgres prefers it over the alias — so the grouping is
        `city` even though the expression is `id`. Testing the expression would
        report a disclosure where there is none, and one of the aliases below
        shadows a real column precisely to exercise that.
        """
        code, out = psql(direct, sql)
        if code != 0:
            return False
        return len([line for line in out.splitlines() if line]) >= rows

    leaks, refused, served, over, elsewhere, rejected = [], 0, 0, [], 0, 0

    def refused_plainly(template: str, expr: str) -> bool:
        """Is the plainest spelling of this query refused as well?"""
        plain = PLAIN_PROJECTING if template.startswith("SELECT {e}") else PLAIN_NONPROJECTING
        return "pgmask:" in psql(proxied, plain.format(e=expr))[1]

    print()
    print("every way to spell a grouping, generated")
    print("----------------------------------------")

    for exprs, expect_refusal in ((KEY_EXPRS, True), (SAFE_EXPRS, False)):
        for expr in exprs:
            for name, template in WRAPPERS:
                for alias in (QUOTED_ALIASES if "quoted" in name else ALIASES):
                    if "{a}" not in template and alias != ALIASES[0]:
                        continue  # alias is irrelevant to this wrapper
                    sql = template.format(e=expr, a=alias)
                    code, out = psql(proxied, sql)
                    if "pgmask:" in out:
                        if expect_refusal:
                            refused += 1
                        elif refused_plainly(template, expr):
                            # Refused for a reason that predates this guard.
                            elsewhere += 1
                        else:
                            over.append((name, expr, alias))
                        continue
                    if code != 0:
                        rejected += 1  # the server rejected it; not our verdict
                        continue
                    if not expect_refusal:
                        served += 1
                        continue
                    # Served a key spelling. Confirm against the server before
                    # calling it a disclosure: a served statement is only a leak
                    # if its grouping really was one row per group.
                    if is_singleton(sql):
                        leaks.append((name, expr, alias, sql))
                    else:
                        served += 1

    # The composite-key half of the predicate. Postgres only: the CockroachDB
    # stand-in carries just `demo.customers`, and the point of running there is
    # the *spellings*, since CockroachDB resolves output aliases in a grouping
    # exactly as Postgres does.
    composite_fail = 0
    if engine != "postgres":
        print()
        print(f"  {DIM}composite-key section skipped on {engine}{OFF}")
        COMPOSITE_CASES.clear()
    print()
    print("composite unique keys")
    print("----------------------------------------")
    for label, expect_refusal, sql in COMPOSITE_CASES:
        code, out = psql(proxied, sql)
        got_refusal = "pgmask:" in out
        if code != 0 and not got_refusal:
            print(f"  {YELLOW}skip{OFF}     {label} {DIM}(server rejected){OFF}")
            continue
        if got_refusal == expect_refusal:
            verdict = f"{GREEN}refused{OFF}" if got_refusal else f"{GREEN}served{OFF} "
            print(f"  {verdict}  {label}")
        else:
            what = "served but must be refused" if not got_refusal else "refused but must be served"
            print(f"  {RED}WRONG{OFF}    {label} {DIM}({what}){OFF}")
            composite_fail += 1

    # The union rule's cost, pinned rather than left to be discovered.
    out = psql(proxied, UNION_OVER_REFUSAL)[1] if engine == "postgres" else "pgmask:"

    if "pgmask:" in out:
        print(f"  {YELLOW}cost{OFF}     disjoint grouping sets over the two key columns")
    else:
        print(f"  {YELLOW}note{OFF}     disjoint grouping sets are now served — the union")
        print(f"           rule changed; confirm that is deliberate")

    proxy.kill()
    if not keep:
        subprocess.run(["podman", "rm", "-f", "-v", container], capture_output=True)

    for name, expr, alias, sql in leaks:
        print(f"  {RED}LEAK{OFF}     {name:<20} {expr}  {DIM}alias={alias}{OFF}")
        print(f"           {DIM}{sql}{OFF}")
    for name, expr, alias in over[:8]:
        print(f"  {YELLOW}OVER{OFF}     {name:<20} {expr}  {DIM}alias={alias}{OFF}")
    if len(over) > 8:
        print(f"  {YELLOW}OVER{OFF}     {DIM}...and {len(over) - 8} more{OFF}")

    print("----------------------------------------")
    print(
        f"  {refused} key spellings refused, {RED if leaks else GREEN}{len(leaks)} leaked{OFF}"
    )
    print(
        f"  {served} non-key served, {len(over)} over-refused by this guard, "
        f"{elsewhere} refused by an older rule"
    )
    print(f"  {DIM}{rejected} rejected by the server, so not our verdict{OFF}")
    if refused == 0:
        print(f"  {RED}FAIL{OFF}: nothing was refused, so this run asserted nothing")
        return 1
    if served == 0:
        print(f"  {RED}FAIL{OFF}: nothing was served, so refusal proves nothing")
        return 1
    return 1 if (leaks or composite_fail) else 0


if __name__ == "__main__":
    sys.exit(main())
