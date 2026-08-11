# Who owns what

pgmask is a proxy layer. It enforces a policy; it does not decide one.

The split matters because getting it wrong in either direction is expensive. If
we shipped opinions about your schema we would be wrong more often than useful.
If you assume we are checking something we are not, you have a gap you do not
know about.

## You own the catalog

You know which of your columns are sensitive. We do not, and we cannot work it
out — a column called `notes` might hold shipping instructions or a support
agent's transcript of a medical call, and nothing in the schema tells us which.

Concretely, yours:

- **Which columns are sensitive**, and how — hidden, redacted, bucketed,
  pseudonymised.
- **Who sees what.** Roles map to usernames Postgres has authenticated;
  which people belong to which role is your call.
- **Keeping the catalog current** as your schema changes.
- **Wiring a check into your CI** so a new column does not go unnoticed. We ship
  the check (`classify --check`); running it is yours.
- **The network boundary.** See [the deployment section of the
  README](../README.md#deploying-it-the-part-that-is-not-code). If people can
  reach Postgres directly, none of this applies to them.

## We own the mechanism

Ours to get right, and ours to be blamed for:

- **The wire protocol.** Reading result sets, rewriting values, forwarding
  everything else untouched.
- **The masks themselves.** That `date-year` produces a valid date, that
  `pseudonym` on a `uuid` produces a valid uuid, that the same input always
  produces the same output so masked data stays joinable.
- **Refusing what we cannot classify**, rather than guessing.
- **Not leaking through the side doors** — `COPY TO STDOUT`, error message
  details, system catalogs, statistics views.
- **Telling you when your catalog stops working**, loudly.

## The safety property you can rely on

**A column that is not in your catalog is hidden, not exposed.**

This is the one that lets you start with an incomplete catalog. Every column
pgmask sees is either something you classified, or something it masks by
default. A gap in your catalog costs you a usable column. It does not leak one.

The inverse is not protected, and cannot be: if you write `mask = "none"` on a
column that turns out to be sensitive, we pass it through. That is the point of
`none` — it is how you say "I looked at this and it is fine." We have no way to
second-guess it, and a proxy that overrode your explicit decisions would be
unusable.

So the risk profile is:

| you did | result |
|---|---|
| forgot a column | it comes back hidden; someone complains it is blank |
| classified it wrongly (too strict) | same — a usability problem |
| marked it `none` and were wrong | **it is exposed** |
| never wrote a catalog at all | everything is hidden; the proxy is useless but safe |

Only one row of that table is a disclosure, and it is the row where you made an
explicit decision.

## Building the catalog

Because unclassified means hidden, a useful catalog has to name **every** column
you want visible, not just the sensitive ones. On a real schema that is hundreds
of entries, which is why there is a tool:

```bash
DSN=postgres://… cargo run -p classify --release -- --schema public --sample 200 > catalog-draft.toml
```

It walks the schema and proposes a classification for every column, then prints
a coverage report on stderr saying what it could not decide. It sorts columns
four ways:

- **confirmed** — the name matched and sampled values agreed
- **likely** — the name is conclusive on its own
- **needs a human** — something is suspicious that a name cannot settle: a free
  text column, a bare `name` that might be a person or a company, an opaque id
- **ordinary** — nothing suggests sensitivity

The report always ends by saying how many landed in *ordinary* and that nothing
verified they are harmless. That is the part you review. The tool is a starting
point that shortens the work; it is not a compliance artifact and does not know
your business.

With `--sample` it reads data, because a column called `notes` full of email
addresses is exactly what name matching misses. Sampled values are counted
against a shape check or a checksum — Luhn for card numbers, mod-97 for IBANs,
the SSA's allocation rules for US Social Security numbers — and thrown away.
**It never prints a value it read.**

A checksum is what makes that worth running on a column whose name says
nothing. A shape test matches roughly one string of digits in one; Luhn rejects
about nine in ten. What content discovery proposes is always `null`, never the
matched shape's mask: knowing the values are payment instruments does not say
whether the column is a card, an IBAN or a bank account, and those are treated
differently. It names the shapes and leaves the narrowing to you.

## Keeping it current

```bash
classify --check --catalog catalog.toml --schema public
```

Exits non-zero when a column exists in the database but not in your catalog, or
when a rule in your catalog no longer matches anything. Run it in CI against a
schema-equivalent database and a new column fails the build instead of silently
turning up blank in someone's dashboard.

Nothing about this is enforced by the proxy at runtime. The proxy stays safe
either way — it hides what it does not recognise — but "safe" and "working" are
different, and the check is what tells you which one you have.

## What we do not do

- **We do not audit your catalog.** If it says `mask = "none"`, that is final.
- **We do not discover sensitivity at runtime.** No content scanning of values
  in flight, no heuristics on live data. Classification is configuration, read
  from your file and refreshed against the database on a timer.
- **We are not a network control.** If your database is reachable around us, we
  are decoration.
- **We are not an access-control system.** Postgres authenticates and authorises;
  we only decide what the rows look like on the way back. Someone with no
  `SELECT` grant sees nothing regardless of what your catalog says, and someone
  with a grant sees whatever your catalog permits.
