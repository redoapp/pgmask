#!/usr/bin/env python3
"""Every way to spell "group by the key", generated rather than remembered.

    ./scripts/test-grouping.py [--keep]

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
import subprocess
import sys
import time

PG_PORT = 55503
PROXY_PORT = 6543
CONTAINER = "pgmask-grouping"
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
    direct = f"postgresql://postgres:demo@localhost:{PG_PORT}/demo"
    proxied = f"postgresql://postgres:demo@localhost:{PROXY_PORT}/demo"

    subprocess.run(["podman", "rm", "-f", "-v", CONTAINER], capture_output=True)
    subprocess.run(
        ["podman", "run", "-d", "--name", CONTAINER, "-e", "POSTGRES_PASSWORD=demo",
         "-e", "POSTGRES_DB=demo", "-p", f"{PG_PORT}:5432",
         "docker.io/library/postgres:17"],
        capture_output=True,
    )
    for _ in range(90):
        if psql(direct, "select 1")[0] == 0:
            break
        time.sleep(1)
    if psql(direct, "select 1")[0] != 0:
        print("FAIL: postgres did not start")
        return 1
    subprocess.run(
        ["psql", "-w", direct, "-q", "-v", "ON_ERROR_STOP=1", "-f",
         f"{ROOT}/examples/demo/schema.sql"],
        capture_output=True, env=dict(os.environ, PGPASSWORD="demo"),
    )

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
    open(config, "w").write("\n".join(rewritten))

    proxy = subprocess.Popen(
        [f"{ROOT}/target/release/pgmask", config],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(4)
    if psql(proxied, "select 1")[0] != 0:
        print("FAIL: proxy did not come up")
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

    proxy.kill()
    if not keep:
        subprocess.run(["podman", "rm", "-f", "-v", CONTAINER], capture_output=True)

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
    return 1 if leaks else 0


if __name__ == "__main__":
    sys.exit(main())
