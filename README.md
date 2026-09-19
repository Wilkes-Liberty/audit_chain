# Audit Chain

## Retention and upgrades

Audit channels share one hash chain. Removing an expired row can break the
verification of records that remain, including records in other channels.
Until a verifiable archival boundary is available, `prune()` preserves records
and returns zero. If eligible rows exist, it logs a warning and adds a persistent
warning to Drupal's status report. A retention value of zero remains a no-op.

Review storage capacity and your retention obligations before upgrading.
This safeguard prevents automatic deletion; it does not implement compliant
archival or erasure. Do not substitute a direct SQL delete or rehash retained
records to make verification pass. Preserve a backup and investigate failures.

Install the append-serialization update introduced in 1.7.2 and replace every
old worker before resuming writes. Mixed old and new workers are not protected
by the same mutex. Run whole-history verification after upgrading; previously
damaged history remains a separate recovery task.

For investigated historical failures, the explicit
[successor-segment workflow](docs/SUCCESSOR_SEGMENTS.md) preserves the old
verdict and creates a separately signed continuation. It requires operator
approval, a reviewed backup and a runtime instance identity. The retention
safeguard does not itself activate recovery or change a historical verdict.

## Introduction

Tamper-evident audit logging for Drupal, usable by any module.

Each entry's hash covers the entry's own content **and the previous entry's
hash**. Any later insertion, deletion or edit breaks that chain and is
detectable by an independent verification pass. With an HMAC key configured,
forging a repair also requires the key — so a database-level edit cannot be
quietly papered over.

This is the artifact a security officer asks for: not "the application says it
logged that", but "here is a record that can be shown not to have been altered
since it was written."

## Why this is its own project

The implementation was extracted from
[MCP Sentinel](https://www.drupal.org/project/mcp_sentinel) 1.13, where it had
grown up as the audit trail for AI-agent traffic. It was never specific to that:
personnel-record reads, permission grants, configuration changes and break-glass
logins all want the same guarantee, and none of them should require installing
an AI-governance module to get it.

MCP Sentinel remains its first consumer.

## Requirements

- Drupal 10.6+ or 11.3+
- [Key](https://www.drupal.org/project/key) — holds the HMAC signing key outside
  exported configuration
- [Encrypt](https://www.drupal.org/project/encrypt) — provides the Encryption
  Profile used for optional at-rest metadata encryption

## Usage

```php
// Any service, controller or hook.
\Drupal::service('audit_chain.logger')->log('personnel', 'field_read', [
  'entity_type' => 'node',
  'bundle'      => 'person',
  'id'          => $node->id(),
  'label'       => $node->label(),
  'field'       => 'field_salary',
]);
```

Inject `Drupal\audit_chain\AuditChainLoggerInterface` rather than calling
`\Drupal::service()` in your own code; the interface is the supported contract
and the service is autowirable by that name.

Evidence-required consumers that must not accept an unsigned precommit should
call `logKeyed()` instead of `log()`. It throws
`AuditChainSigningUnavailableException` and writes nothing when the signing key
will not resolve. `signingStatus()` returns `{keyed, key_id}` for cheap
precondition checks. Ordinary auditing should keep using `log()`, which
prefers an unsigned row over a dropped one **when the only fault is signing**.

Serialization is not optional. Both `log()` and `logKeyed()` take a
transaction-scoped mutex before reading the chain head, and hold it until the
wrapping database transaction commits or rolls back. A missing mutex throws
`AuditChainAppendException` and writes nothing; a deadlock or lock timeout
surfaces as a database exception — also a refused write, not a fork.
Evidence-required callers must abort the governed action on either failure.
The request-scoped collector is not a durable retry queue.

A Drupal lock-backend lease cannot cover that commit boundary: it can expire,
or commit on a different connection, while the caller's transaction is still
open. Do not reintroduce one.

Update `10003` creates and seeds the mutex table only. Quiesce appends (web,
cron, queue, CLI), apply the update, replace every old worker, then resume
traffic. A 1.7.x process does not take the mutex and can still fork against a
patched one. The mutex row is not created lazily on the append path: concurrent
first-writers would race on INSERT. The transaction contract, consumer
obligations, and the lock-backend defect are in
[docs/APPEND_SERIALIZATION.md](docs/APPEND_SERIALIZATION.md).

`entity_type`, `bundle`, `id` and `label` are promoted to their own indexed
columns; every other key is serialised into `metadata`. All of it — plus the
actor, timestamp, IP and user agent — is covered by the hash.

**The `channel`** (`'personnel'` above) identifies the consumer. It is bound
into the hash, so an entry cannot be re-attributed to a different channel after
the fact — which matters when one channel is the thing being audited.

### Verifying

```bash
drush audit-chain:verify
```

Exit code is the contract: non-zero means the chain does not verify. Wire it
into monitoring or a deploy gate without parsing the output.

Two different failures are reported differently, because they call for different
responses:

- **BROKEN at row N** — a row's content or ordering no longer matches its hash.
  Something was inserted, deleted or edited.
- **UNSIGNED — N of M entries** — the rows are intact and in order, but were
  hashed without the configured signing key, so anyone with database access can
  rewrite them. Nothing was edited. This almost always means the Key entity did
  not resolve in the environment that wrote them; the status report flags that
  condition while it is still happening.

Both exit non-zero. Entries already written unsigned cannot be signed
retrospectively.

### Exporting evidence off-system

Local-only evidence shares fate with the system it audits: whoever reaches the
database reaches the record of the reach. The exporter moves the durable copy
outside that trust boundary:

```bash
drush audit-chain:export --destination=https://evidence.example.com/ingest
drush audit-chain:export --destination=/var/evidence/chain.ndjson --from-id=1
```

Or enable *Export evidence off-system on cron* and every cron run pushes rows
written since the last successful delivery. Either way the contract is the
same:

- **Versioned NDJSON.** One JSON object per row, each stamped with
  `contract_version` so a consumer can detect shape changes. An `https://`
  destination receives the batch as a single `application/x-ndjson` POST; a
  file path is appended under an exclusive lock. Plain `http://` is refused
  except to loopback (an on-host collector) — evidence does not travel
  unencrypted off-host. Ingest URLs are logged and checkpointed with
  credentials stripped, so a token embedded in the URL never reaches logs or
  state.
- **Data-minimized.** Exported rows carry identifiers and the hash-chain
  columns only — `metadata`, IP addresses, user agents and entity labels never
  leave the system. The trade is deliberate: the off-system copy cannot
  recompute `row_hash` (the canonical payload includes metadata), so chain
  verification stays an on-system duty.
- **Verification-gated.** While the last scheduled verification is failing,
  export refuses rather than presenting unverified rows as evidence. Resolve
  the integrity failure first.
- **At-least-once.** The per-destination checkpoint advances only after a
  delivery succeeds. An outage leaves it in place and the next run retries the
  same rows; a crash between delivery and checkpoint re-sends the overlap.
  Consumers must deduplicate on the row `id` — a duplicate is expected, a gap
  is not. `--limit` caps a run and stays resumable; `--from-id` replays
  history without ever moving the checkpoint backwards.

### Rotating the signing key

Verification accepts a row signed by the current key **or** by any key listed
under *Retired signing keys*. Add the old key there before changing the signing
key, or every row written under it becomes indistinguishable from tampering.

Retired keys are trusted because they come from configuration. The `key_id`
recorded on each row is only a hint about which key to try first — it is not
covered by the row hash, so treating it as proof would let anyone who can write
to the table blank it, recompute the row unkeyed, and have the edit accepted.

## Two constraints every consumer must respect

**1. Do not log per access check.** A hook like `hook_entity_field_access()`
fires per field, per entity, per render. Writing an entry each time produces a
chain nobody can read and a write-amplified request — the log stops being
evidence and becomes noise. The damage is not reversible: you cannot un-flood a
hash chain without breaking it.

Use the collector rather than hand-rolling this. It deduplicates per request and
flushes once at `kernel.terminate`, so the obvious call is the correct one:

```php
// Anywhere during the request — call it as often as the hook fires.
\Drupal::service('audit_chain.collector')->collect('personnel', 'field_read', [
  'entity_type' => 'node',
  'id' => $entity->id(),
  'field' => $field_name,
]);
```

Deduplication is by channel, operation and the promoted entity keys, so forty
field checks on one node become one entry. Pass a fourth argument to widen or
narrow that key. The first occurrence wins — its metadata is kept and later ones
are discarded rather than merged, because a read that happened forty times is
still one read, and merging would invent a record of something nobody did.

Writing happens after the response is sent, which also keeps the append mutex
off the user's critical path.

**2. Rotating the encryption profile orphans existing entries until you re-encrypt.**
Metadata encrypted under profile A cannot be read with profile B alone. The
chain is computed over the *plaintext*, so verification needs that plaintext —
each row records which profile produced its ciphertext, the status report
WARNs when any row still names a retired profile, and
`drush audit-chain:reencrypt --from=A --to=B` rewrites those rows in place
without touching hashes. Keep profile A loadable until re-encrypt finishes.

## Reports dashboard

**Reports → Audit Chain** (`/admin/reports/audit-chain`), gated by the
restrict-access permission *View Audit Chain reports*.

The page is integrity, not an operational log. It shows the last
scheduled-verification verdict and the keyed-vs-unkeyed split over a `24h` /
`7d` / `30d` window. It does not chart volume, channel mix, or operations —
those belong in dblog or a consumer dashboard, not on the evidence chain.
Counts use indexed `timestamp` and `key_id` only. Metadata, IP addresses,
user agents and entity labels are never queried. The integrity card does
**not** re-walk the chain on page load.

The keyed split is inline SVG by default. Installing
[Charts](https://www.drupal.org/project/charts) together with a library
submodule (for example `charts_chartjs`) upgrades it to an interactive chart
with no code change. Enabling `charts` without a library plugin keeps the SVG
fallback — the page will not print "No charting library found".

## Optional MCP tools

`audit_chain_mcp` exposes [Tool API](https://www.drupal.org/project/tool)
plugins so an operator or a governed agent can ask over MCP whether the chain is
healthy. It depends on Tool API and
[MCP Sentinel](https://www.drupal.org/project/mcp_sentinel). MCP Sentinel
depends on Audit Chain, so the tools live in a submodule and the base module
depends on neither. The submodule declares Drupal `^10.6 || ^11.3`, the range
MCP Sentinel declares.

| Tool | Operation | OAuth scope | Returns |
| --- | --- | --- | --- |
| `audit_chain_status` | read | `mcp_read` | How the last scheduled verification classifies and when it ran, the last verdict, whether new entries are signed, the sealed-through position, recovery successor status |
| `audit_chain_window_counts` | read | `mcp_read` | Total, keyed and unkeyed entry counts for `24h`, `7d` and `30d`, or for one of them |
| `audit_chain_export_status` | read | `mcp_read` | Whether cron export is enabled, the export checkpoint, and how many entries are waiting |
| `audit_chain_verify_now` | trigger | `mcp_write` | Runs scheduled verification now and returns the verdict |

MCP Sentinel derives the scope from the operation each tool declares. It treats
a trigger as modifying, so `audit_chain_verify_now` needs the write scope even
though verification never changes the chain.

- Grant `use audit chain mcp tools` to the role your MCP credential uses.
  `audit_chain_verify_now` also needs `run audit chain verification via mcp`.
  Both are restricted permissions.
- MCP Sentinel's gates apply first: permission, source readiness, scope, IP
  policy and rate limit. A tool is listed only for an account that can run it.
- No tool returns a row, metadata, an IP address, a user agent, an entity
  label, a row hash, the seal MAC, the prefix digest, a key identifier, the
  seal's reason or a recovery incident reference. Verdict and successor reasons
  are reported from the module's own fixed list; any other stored value reads
  `other`. `broken_at` is a row id.
- Status and window counts read the dashboard metrics service. That service
  logs a failed query and degrades to `pending` or zero instead of throwing, so
  the tools do too. Zero on a busy site is a reason to read the log.
- The export destination is reported as its kind (`https`, `http` or `file`)
  and, for a URL, its host. The path, port, credentials and query string are
  left out, because ingest services put tokens in paths. A file path is never
  returned.
- Verification reads every row past the seal and decrypts its metadata, so its
  cost grows with the table. The profile rate limit applies. A call within 60
  seconds of the last recorded run returns that run with `"ran": false` and
  does not walk the table again. A run through the tool is recorded exactly as
  a cron run is: a failure is logged and `AuditChainVerificationFailedEvent`
  fires.
- A refusal from this module is one fixed message. Tool API and MCP Sentinel
  have their own messages for invalid input, denied access and rate limits.
  None relays an input value.
- Installing the submodule publishes nothing by itself. Enable the tools in
  your site's MCP tool bridge configuration.

Not available as tools, by design:

- Sealing a prefix, preparing or activating recovery, re-encryption and
  pruning. Each is permanent and is built around a person confirming it.
- Export to a destination the caller supplies. That would send evidence
  wherever an agent names.
- Writing a log entry. An agent must not be able to forge evidence.
- Any reader of rows or metadata. IP addresses, user agents and decrypted
  metadata are personal data.

## Configuration

**Configuration → System → Audit Chain** (`/admin/config/system/audit-chain`).

| Setting | Effect |
|---------|--------|
| Signing key | A Key entity. Empty means plain SHA-256 — enough to detect accidental corruption and careless edits, not enough to stop someone with database access recomputing the chain. Store the key outside the database (File or Environment provider). A key that is set but will not resolve is reported as an error on the status report, and every entry written meanwhile is unsigned. |
| Retired signing keys | Keys this chain was signed with previously. Verification accepts a row signed by any of them, so rotating does not make earlier rows look tampered with. Removing one makes the rows it signed unverifiable. |
| Encryption profile | Encrypts `metadata` at rest. See the rotation caveat above. |
| Stream entries | Emits each entry to the `audit_chain` logger channel as a structured record, so syslog or Monolog can forward to a SIEM without polling. |
| Scheduled verification interval | Runs a full chain verification on cron at most this often (`0` disables). An integrity failure is an error on the status report, an alert on the `audit_chain` channel, and an `AuditChainVerificationFailedEvent` — the chain itself is never modified by the check. A foreign seal is a fail-closed warning; see below. |
| Require keyed verification | The enterprise assurance profile: scheduled verification fails — instead of falling back to unkeyed SHA-256 — when no signing key resolves or when rows were written unkeyed. |
| Export evidence off-system on cron | Pushes new chain rows to the export destination after each cron run. See *Exporting evidence off-system* for the delivery contract. |
| Export destination | An `https://` ingest URL or a server file path. |
| Export channel filter | Restricts the cron export to one channel partition; empty exports all channels. |

## Sealing an unverifiable prefix

If history was written unkeyed (or is otherwise not verifiable under today's
signing keys), **do not re-chain it**. Recomputed hashes would paper over
tampering. Instead:

```bash
drush audit-chain:seal --through=1997 --reason="pre-key unkeyed production segment"
drush audit-chain:verify
```

The seal is a site-local genesis anchor over stored `row_hash` values. It proves
nothing about the past; it makes any *future* change to that prefix's stored
hashes detectable and lets post-seal verification exit cleanly. Only rows that
do **not** verify under the configured keys may be sealed.

### Database refreshes and foreign seals

A database refresh copies the seal in Drupal state, but a sound environment
separation policy usually does not copy the production HMAC key. On the target,
`drush audit-chain:verify` therefore reports `SEAL FOREIGN` when the stored
prefix hashes still match the copied seal digest but no current or retired key
can authenticate its MAC.

This result stays fail-closed: `verify()` returns `ok: false` with reason
`seal_foreign`, Drush exits non-zero, and evidence export remains blocked. It is
reported as a warning and does not dispatch
`AuditChainVerificationFailedEvent`, because unchanged copied hashes are not by
themselves evidence of tampering. The seal is still unauthenticated on the
target and could itself have been altered, so production remains the authority:
verify there before relying on the prefix. If policy explicitly permits the
target to hold the source signing material, adding that Key entity to *Retired
signing keys* authenticates existing seals and rows without using it for new
writes. Do not copy a production key merely to make a refreshed environment
green.

If any stored `row_hash` in the sealed prefix changes relative to the seal,
verification instead reports `SEAL BROKEN`; scheduled verification keeps the
error log and failure-event behavior for that integrity incident.

## What it does not do

- **It does not make deletion impossible.** Nothing at the application layer
  can. It makes deletion *evident*: the seam is visible at the next verify.
  Pruning is therefore an explicit, channel-scoped operation, and it leaves a
  seam by design.
- **It does not order events across servers.** The chain is a single sequence
  in one database.
- **It is not a replacement for `dblog` or syslog.** Those are operational
  logs. This is an evidentiary one, and it is deliberately narrower.

## Maintainers

- [Jeremy Michael Cerda](https://www.drupal.org/u/jmcerda) — <jmcerda@wilkesliberty.com>
- Wilkes & Liberty, LLC — [drupal.org/u/wilkes-liberty](https://www.drupal.org/u/wilkes-liberty)
