# ScrubKit

Strip secrets and PII out of text **before** you paste it into an AI chat — and put the
real values back into the model's reply.

Zero dependencies. Runs identically in the browser and in Node. MIT licensed.

```js
const ScrubKit = require('./scrubkit.js');

const { text, map } = ScrubKit.redact(
  'db: postgres://svc:9Kx@orders-db-01.corp.internal:5432/orders, paged dev.ops@northwind.com'
);

text // → 'db: [DB_URL_1], paged [EMAIL_1]'

// …send `text` to the model, get an answer back, then:
ScrubKit.restore(modelReply, map)   // real values return
```

---

## The problem

You paste a stack trace into ChatGPT. It has a connection string in it. You paste a
customer's support email into Claude. It has their card number in it. You do it a dozen
times a week, because the alternative is doing the work yourself.

Most "redact before you paste" scripts are a pile of regexes, so they flag `3.11.9` as a
phone number and every 16-digit order ID as a credit card. You stop trusting the output,
and then you stop using the tool.

## What makes this one different

**1. It validates instead of guessing.**

| Type | Check |
|---|---|
| Payment cards | Luhn checksum **and** a real issuer prefix |
| IBANs | mod-97 |
| US SSNs | rejects impossible area/group/serial blocks and known dummies |
| IPv4 | octet-checked; private ranges are a separate opt-in detector |
| `secret = "..."` | entropy-gated, so `changeme`, `********` and `process.env.API_KEY` are ignored |
| Overlaps | resolved by priority, so a Postgres URL is redacted as one unit, not shredded into a host, a password and a port |

That's why your version numbers, dates and order IDs survive.

**2. It's reversible.**

Values become *stable placeholders* — the same value always gets the same token across
the whole document:

```
18:42  dsn=[DB_URL_1]
18:44  rollback 3.11.9 → 3.11.8 from [IPV4_PUBLIC_1]
18:51  paged [EMAIL_1] ([PHONE_1])
       order #88213 for [EMAIL_2] failed twice
```

Three log lines mentioning the same host still read as the same host, so the model can
actually reason about it. Then `restore()` turns the answer back into something you can
act on. Deleting the values would destroy the question.

---

## Install

There is nothing to install. Copy `scrubkit.js` into your project, or:

```html
<script src="scrubkit.js"></script>
<script>ScrubKit.redact(text)</script>
```

Requires Node 16+ if you're using it server-side.

## API

### `redact(text, options?)`

Returns `{ text, map, findings, stats, count }`.

```js
const r = ScrubKit.redact(input, {
  enabled: ['email', 'gh_token', 'credit_card'],          // default: all but the opt-ins
  custom:  [{ id: 'emp', label: 'Employee ID',
              pattern: '\\bEMP-\\d{6}\\b' }],             // your own patterns
  placeholder: (label, i, id) => `<<${id}:${i}>>`         // your own token format
});
```

Each finding is `{ id, label, group, value, token, start, end }`.

### `restore(text, map)`

Swaps placeholders back for the original values. Longest-token-first, so overlapping
token names can't corrupt each other.

### `ScrubKit.detectors`

The full detector list — `{ id, label, group, defaultOff }` — for building your own UI.

---

## What it catches

**Credentials** — AWS keys and ARNs · GitHub PATs · OpenAI, Anthropic, Google and Hugging
Face keys · Slack tokens and webhooks · Discord webhooks · Stripe keys · Twilio SIDs ·
SendGrid · npm, PyPI and GitLab tokens · JWTs · private key blocks

**Connection strings** — Postgres, MySQL, MongoDB, Redis, AMQP, MSSQL, ClickHouse · any
URL carrying `user:password@`

**Personal data** — emails · phone numbers · payment cards · IBANs · US SSNs

**Infrastructure** — public IPv4 · IPv6 · MAC addresses · optional private IPs and UUIDs

## What it does *not* catch

People's names and free-form street addresses. Those need a language model, not a regex,
and a tool that claims otherwise from patterns alone is overselling.

ScrubKit deliberately sticks to things it can *validate*, which is exactly why you can
trust what it does flag. **Read the output before you send it.** This is a safety net,
not a compliance product, and it makes no guarantee of completeness.

---

## Tests

```
node test.js
```

51 tests covering detection, checksum validation, false-positive suppression
(version numbers, dates, semver, order IDs, placeholder secrets), overlap resolution,
round-trip fidelity, idempotency and a realistic mixed document.

## The browser tool

`index.html` is the whole thing as one self-contained file — scrub on one tab, restore
the model's reply on the other. Open it locally with your Wi-Fi off and it still works,
which is the easiest way to prove nothing is being uploaded.

Hosted copy: <https://codecraft143.gumroad.com/l/scrubkit-free>

## Going further

This repo is the engine and the browser tool. If you need it across **whole folders,
repos and commits**, the [ScrubKit Pro Pack](https://codecraft143.gumroad.com/l/scrubkit)
adds a batch CLI (`scan` / `scrub` / `restore` over directories, with line numbers and
JSON output for CI), a pre-commit hook that blocks commits containing live credentials,
custom rule packs, saved mapping files, and a GitHub Actions recipe.

## Licence

MIT — see [LICENSE](LICENSE).
