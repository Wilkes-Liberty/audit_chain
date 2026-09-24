# Changelog

All notable changes to Audit Chain are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- Uninstall deletes module-owned state (`audit_chain.seal`,
  `audit_chain.scheduled_verification`, `audit_chain.retention_refused`,
  and `audit_chain.export_checkpoint.*`). Schema tables already drop; a
  leftover seal made a later empty-chain `verify()` report `seal_broken`.

## [1.10.0] - 2026-09-22

### Added
- Versioned global archive checkpoints and independently verifiable archive
  bundles (#3624875). Contract v1 commits to a deterministic Merkle root over
  row ids and stored hash-chain columns, the window chain head, and bounded
  commitments to any existing prefix seal or successor record. Bundles include
  inclusion proofs, a JSON Schema, and an offline verification recipe without
  metadata, IP addresses, user agents, entity labels, channel names, actors,
  entity identifiers, or key identifiers.
- A digest-only `WitnessBackendInterface`, immutable receipt and verdict values,
  persisted opaque receipt placeholders, and a NoOp backend (#3624875). Missing
  configuration remains pending and fails verification; witness operations make
  no network request and add no audit-chain row.
- `docs/ARCHIVAL_BOUNDARY.md` documents v1 canonicalization, the limits of the
  existing NDJSON stream, offline bundle verification, and what a future
  witness can and cannot prove.

### Changed
- Clarified that `prune()` remains a no-op in 1.10 even when eligible rows
  exist. A checkpoint or receipt does not authorize deletion (#3624875).
- Drupal support remains `^10.6 || ^11.3`. Drupal 12 is not claimed because the
  current stable Key and Encrypt dependencies, and the optional MCP Sentinel
  integration, do not yet provide a CI-testable Drupal 12 dependency set.

## [1.9.1] - 2026-09-19

### Changed
- `RecoverySegments` reuses `snapshot()`'s historical verdict in `prepare()`
  and `activate()` so the shared lock does not walk the chain a second time.
  `snapshot()` still calls `verify()`; that verdict remains part of
  `snapshot_digest`.

## [1.9.0] - 2026-09-19

### Added
- Optional `audit_chain_mcp` submodule: four Tool API plugins governed by MCP
  Sentinel (#3624446). `audit_chain_status`, `audit_chain_window_counts` and
  `audit_chain_export_status` are read-only. `audit_chain_verify_now` runs
  scheduled verification and needs its own permission. No tool returns a row,
  metadata, a hash, the seal MAC, the prefix digest, a key identifier or the
  export destination's path or credentials. The base module's dependencies are
  unchanged. The submodule requires Tool API and MCP Sentinel and declares
  Drupal `^10.6 || ^11.3`.
- `EvidenceExporter::checkpointStatus()` reads a destination's checkpoint and
  backlog without exporting. It does not return the stored destination label.

## [1.8.3] - 2026-09-18

### Fixed
- Scheduled-verification integrity classification is shared by the
  dashboard and status report. Date formatting is skipped unless the
  integrity state shows a run time.

## [1.8.2] - 2026-09-17

### Fixed
- Apply the global Drush confirmation fix to the older prefix-sealing command
  as well (#3623864). Installed CLI coverage checks command discovery, explicit
  refusal without a seal, and refusal to reseal frozen successor history.

## [1.8.1] - 2026-09-17

### Fixed
- Recovery activation uses Drush’s global confirmation options instead of
  declaring a second `--yes` option (#3623864). The duplicate prevented the
  command from running. `--no` refuses activation; `--yes` confirms the
  historical exception through Drush’s normal confirmation handler.

## [1.8.0] - 2026-09-17

### Added
- Explicit signed successor segments for reviewed historical failures
  (#3623864), with snapshot approval, an append-only recovery record and
  transaction-serialized activation. Dedicated Drush commands prepare,
  activate, verify and export the recovery record. Original rows, hashes,
  seals and whole-history failure remain unchanged. Scheduled monitoring and
  the dashboard distinguish successor health from the historical exception.
  Run database updates and configure a unique runtime instance identity before
  activation. See docs/SUCCESSOR_SEGMENTS.md for the recovery procedure.
  Once activated, bulk re-encryption and resealing refuse to change the frozen
  evidence. Both maintenance paths now share append serialization.

### Fixed
- Refuse destructive per-channel pruning while no verifiable archival boundary
  exists (#3623864). Eligible records are retained, with a log warning and a
  persistent status-report warning. Channels share one chain; deleting expired
  rows could invalidate another channel's history or a prefix seal. Review
  retention obligations and disk capacity when upgrading. Existing failures
  are not repaired or hidden.

## [1.7.2] - 2026-09-16

### Fixed
- **Appends no longer proceed without serialization (d.o. #3623694).** Both
  `log()` and `logKeyed()` take a transaction-scoped mutex on
  `{audit_chain_mutex}` before reading the chain head, so concurrent writers
  cannot share a `prev_hash`. The mutex is held until the wrapping database
  transaction commits or rolls back, which an expiring lock-backend lease
  cannot do. A missing mutex throws `AuditChainAppendException` and writes
  nothing; deadlock and lock-timeout failures still abort the write. Existing
  hashes and seals are not rewritten. The logger constructor no longer takes
  the lock backend. Run update 10003 and replace every old worker before
  resuming traffic: a 1.7.x process does not take the mutex and can still
  fork against a patched one. CI runs the kernel suite on PostgreSQL 16 and
  MySQL 8.0 as well as SQLite so the cross-process serialization tests execute.

## [1.7.1] - 2026-09-15

### Changed
- **verify() and sealPrefix() share one stored-row canonical helper.** Hashing of
  existing rows for verification and prefix sealing now goes through a single
  `canonicalFromRecord()` path so the two cannot drift. Hash format, locking,
  and schema are unchanged.

## [1.7.0] - 2026-09-11

### Added

- **Integrity reports page with optional Charts API upgrade (#32 / d.o. #3622590).** A
  read-only page at `/admin/reports/audit-chain` shows chain integrity
  (from the last scheduled verification — it does not re-walk the chain on
  GET) and the keyed-vs-unkeyed split over a `24h` / `7d` / `30d` window.
  It is not an operational volume dashboard: channel mix, operation mix,
  and time-series charts are omitted on purpose. Counts use indexed
  `timestamp` / `key_id` only; metadata, IP addresses, user agents and
  entity labels never appear. The keyed split upgrades to `drupal/charts`
  when a library plugin is present and keeps an inline-SVG fallback when
  Charts is absent or enabled without a library. Gated by the
  restrict-access permission `view audit chain reports`.

## [1.6.0] - 2026-09-02

### Added

- **Strict keyed append and signing-status API (#25 / d.o. #3620484).**
  `AuditChainLoggerInterface::logKeyed()` appends only when the row will be
  HMAC-signed with the currently configured key; otherwise it throws
  `AuditChainSigningUnavailableException` and writes nothing. Ordinary
  `log()` is unchanged (unsigned row beats a lost one).
  `signingStatus()` returns `{keyed, key_id}` from the chain's own key
  resolution so evidence-required consumers (e.g. mcp_sentinel's
  evidence-required veto) do not duplicate Key-entity lookup.

## [1.5.1] - 2026-08-25

### Fixed

- **Cross-environment prefix seals no longer create false tampering alarms
  (d.o. #3616792).** Verification now distinguishes a changed sealed-prefix
  digest (`seal_broken`) from a digest that still matches but whose MAC cannot
  be authenticated under the target environment's current or retired keys
  (`seal_foreign`). Foreign seals remain fail-closed: the command exits
  non-zero, scheduled state records `ok: false`, and evidence export stays
  blocked. They surface as an operational warning without dispatching the
  integrity-failure event; real prefix-hash changes remain errors and events.
  Seal verification also no longer accepts an unkeyed MAC, because the sealing
  API requires a resolvable signing key and accepting an unsigned substitute
  would let database access rewrite the prefix and its anchor together.

## [1.5.0] - 2026-08-14

### Added

- **Off-system evidence export (#18 / d.o. #3616535, part 2).** Chain rows can
  now leave the writer's trust boundary as versioned, data-minimized NDJSON —
  identifiers and hash-chain columns only; `metadata`, IP addresses, user
  agents and entity labels never leave the system. Destinations are an
  `https://` ingest URL (one `application/x-ndjson` POST per batch) or a file
  path (appended under an exclusive lock). Delivery is at-least-once with a
  per-destination checkpoint that advances only after a successful delivery:
  an outage leaves it for retry, `--limit` runs are resumable, and `--from-id`
  replays history without ever moving the checkpoint backwards — consumers
  deduplicate on the row `id`. Export refuses while the last scheduled
  verification is failing, so unverified rows are never presented as
  evidence. Run it with `drush audit-chain:export`, or enable the cron leg
  (`export_enabled` + `export_destination`, optional `export_channel`
  partition filter); cron verifies before it exports, so a failure discovered
  on the same run already blocks the push. Plain `http://` destinations are
  refused except to loopback, HTTP delivery is bounded by connect/read
  timeouts, and ingest URLs are logged and checkpointed with credentials
  stripped. This completes d.o. #3616535 — part 1 (scheduled keyed
  verification) shipped in 1.4.0.

## [1.4.0] - 2026-08-14

### Added

- **Scheduled keyed verification with durable health and an alert contract
  (#18 / d.o. #3616535, part 1).** Cron now runs a full chain verification on
  a configurable interval (`verify_interval`, disabled by default). Each run
  records its verdict in state and on the status report: a failure is a
  REQUIREMENT_ERROR, a schedule gone quiet (no run within twice the interval)
  or never-yet-run is a WARNING, and a pass reports its last-run time. A
  failure also logs an error to the `audit_chain` channel (SIEM-forwardable)
  and dispatches `AuditChainVerificationFailedEvent` so consumers bind their
  own alerting — the chain itself is never modified by the check. The
  enterprise assurance profile (`verify_require_keyed`) refuses unkeyed
  operation outright: no signing key means a stable
  `keyed_verification_unavailable` failure instead of an unkeyed fallback,
  and unkeyed history fails it too. Rotated keys keep verifying through
  `previous_hash_keys`. The off-system stream/export contract is part 2 of
  the same issue.


### Changed

- **CI: the attribution check is now the shared workflow.**
  `.github/workflows/attribution.yml` becomes a thin caller pinned to
  `Wilkes-Liberty/shared-ci@v1`, and the vendored `.github/scripts/` copies are
  removed. One implementation for every repository makes copy drift structurally
  impossible instead of merely detectable.

## [1.3.0] - 2026-07-31

### Added
- **Prefix seal for unverifiable history (#5 / d.o #3614137).**
  `drush audit-chain:seal --through=ID --reason="…"` records a keyed digest over
  the *stored* `row_hash` values of a historical prefix that does not verify
  under the configured signing keys (typically unkeyed production rows).
  `verify()` then content-checks only post-seal rows, reports
  `sealed_through` / `seal_intact` / `verified_from`, and exits 0 when the seal
  is intact and the live segment verifies — without re-chaining. Editing a
  sealed hash fails as `seal_broken`. Status report WARNING when a seal is
  active. Sealing a still-verifiable row is refused.

## [1.2.0] - 2026-07-31

### Added
- **`drush audit-chain:reencrypt --from=… --to=…` (#2 / d.o #3613978).** Re-encrypts
  stored metadata from one EncryptionProfile to another without touching
  `row_hash` or any column covered by the hash. Batched via `--limit` for
  resumable runs; refuses to start unless both profiles load. Completes the
  rotation story started in 1.1.0 (status-report WARNING when rows lag behind
  the configured profile).

### Fixed
- **`decodeMetadata()` / `verify()` use each row's recorded encryption profile.**
  After a rotation, ciphertext written under the previous profile is decrypted
  with that profile first, not only the currently configured one — so keeping
  the old EncryptionProfile entity available is enough to keep historical
  rows readable and verifiable until re-encrypt finishes.

## [1.1.0] - 2026-07-30

### Added
- **A request-scoped collector, so the obvious integration is the correct one.** The driver
  for extracting this module was a consumer recording reads of access-controlled fields —
  the single worst case for naive logging, because `hook_entity_field_access()` fires per
  field, per entity, per render. A per-call `log()` turns one human action into dozens of
  entries, and a flooded hash chain cannot be un-flooded: you cannot remove rows without
  breaking it.

  Documentation saying "do not do the obvious thing" is weaker than an API where the obvious
  thing is safe, so `audit_chain.collector` buffers per request, deduplicates, and writes
  once at `kernel.terminate`.

  Deduplication is by channel, operation and the promoted entity keys, overridable per call.
  The first occurrence wins rather than the last, and metadata is **not** merged: a read that
  happened forty times is still one read, and a synthesised union would describe an action
  nobody took.

  Writing after the response also keeps the chain's append lock off the request's critical
  path — it serialises across the whole site, so holding it mid-request makes concurrent
  requests wait on work none of them needs.

  The README's "Two constraints every consumer must respect" now leads with this rather than
  with a warning.
- **The status report now warns when entries were encrypted under a profile the site no
  longer uses.** Rotating an encryption profile is ordinary key hygiene — a compliance
  regime may require it on a schedule — and it silently orphans everything written under the
  previous one. Nothing looks broken: the rows are still there and the chain still verifies,
  because the chain covers the plaintext and not the ciphertext. The loss surfaced only when
  someone opened an old entry, which is exactly the moment an audit trail is supposed to
  work.

  Each row now records the profile that actually encrypted it (`encryption_profile`, empty
  when stored as plaintext), so the check names the profile to restore rather than guessing.
  It records what produced the stored bytes, not what was configured: a row whose encryption
  threw and fell back to plaintext is recorded as plaintext, so a future re-encrypt pass is
  not sent looking for ciphertext that was never written.

  Reported at WARNING, not ERROR — the entries are intact and chain integrity is unaffected;
  what is lost is readability. Existing rows are left unrecorded rather than backfilled from
  the current setting, because which profile encrypted a historical row is not knowable from
  configuration, and that gap is the entire point of the column.

  There is still no re-encrypt command, so this converts a silent trap into a visible one
  rather than implying a fix exists.
- **`key_id` on each row**, recording which Key entity's material produced the hash
  (empty when hashed unkeyed). Advisory only: it is not covered by the row hash — it
  could not be, without invalidating every row written before it existed — so
  verification treats it as a hint about which key to try first and never as proof.
  Trusting it would let anyone able to write to the log blank it, recompute the row
  unkeyed, and have the edit accepted.
- **`verify()` returns three more keys** — `reason`, `unkeyed_rows` and `unkeyed_through` —
  alongside the existing `ok` and `broken_at`. Purely additive, so code reading the keys it
  needs is unaffected. Code comparing the **whole array** (`assertSame(['ok' => TRUE,
  'broken_at' => NULL], …)`) will need updating; `mcp_sentinel` had exactly one such
  assertion and it is the reason this note exists.
- **Retired signing keys (`previous_hash_keys`).** Verification accepts a row signed by
  the current key or any retired one, so rotating the signing key no longer makes every
  earlier row indistinguishable from tampering. Retired keys are trusted because they
  come from configuration, which an attacker editing the log table does not control.

### Fixed
- **A signing key that is configured but will not resolve no longer downgrades the
  chain in silence.** `resolveHashKey()` returned an empty string both when no key was
  configured and when a configured key could not be resolved. The two produce the same
  hash and mean opposite things, so a site could believe it had a signed, tamper-evident
  chain while every row went in unsigned, with nothing anywhere to notice.

  Found on a real deployment: 1,997 of 2,002 rows verified under plain SHA-256 and none
  under HMAC. The key resolved fine by the time anyone looked, which made the diagnosis
  worse rather than better — see below.

  Now every write with an unresolvable key logs an error naming the key, and
  `hook_requirements()` reports the condition on the status report at ERROR. The entry
  is still written: dropping an audit record is a worse failure than an unsigned one.
- **`drush audit-chain:verify` no longer reports unsigned rows as tampering.** Once the
  key resolved, verification recomputed those historical rows under HMAC and announced
  *"BROKEN at row 1 — an entry has been inserted, deleted or edited"*. Nothing had been
  edited. `verify()` now distinguishes a row whose content or ordering no longer matches
  its hash (`tampered`) from one that is intact but was hashed without the key
  (`written_unkeyed`), and reports how many rows and through which id.

  Both still exit non-zero — a chain the site believes is signed and is not is a real
  finding — so the documented exit-code contract is unchanged. Only the diagnosis is,
  and with it whether an operator goes looking for an intruder who does not exist.
- **Metadata that is not valid UTF-8 no longer produces a permanently unverifiable
  row.** `json_encode()` returns `FALSE` on a single malformed byte and the `(string)`
  cast turned that into `''`, so both the stored metadata and the canonical payload
  became empty and the row was hashed over nothing. It could never verify again, and
  nothing reported it. Five rows on the same real deployment were lost this way — all
  `entity_save` on nodes whose field values carried a truncated multibyte character.

  The canonical payload and the stored metadata now use `JSON_INVALID_UTF8_SUBSTITUTE`.
  Existing rows are unaffected: a payload that was already valid UTF-8 encodes to
  exactly the same bytes with or without the flag, so no historical hash changes. Rows
  already written this way cannot be recovered — their content is gone, not merely
  unreadable.

## [1.0.2] - 2026-07-30

### Changed
- **`composer.json` now declares `"php": ">=8.1"`.** It previously specified no PHP
  constraint at all, so the effective floor came only from whatever core happened to
  require — the supported surface was implied rather than stated, and a reader had to
  trace Drupal's own requirements to find it.

  8.1 is the real floor, checked rather than assumed: PHPCompatibility reports the
  codebase clean from 8.1 upward, Drupal 10.6 requires `>=8.1.0`, and neither
  `drupal/key` nor `drupal/encrypt` declares a PHP constraint of its own. It is also
  already verified — the drupal.org previous-major lane runs this suite on PHP 8.1.34
  and passes, so this is a claim CI exercises rather than one it merely tolerates.

  This does not change which sites can install today: `^10.6 || ^11.3` already implies
  the same floor. What it changes is that the claim is stated where Composer and a
  human both read it, and it stops moving silently if core's floor moves or this
  module adopts newer syntax.

## [1.0.1] - 2026-07-29

### Fixed
- **The streamed SIEM record carries `bundle` again.** 1.0.0 dropped it in the
  move out of MCP Sentinel, where it had always been emitted. Nothing failed
  and nothing warned — a SIEM rule keyed on `bundle` would simply have stopped
  matching, which is the worst way for an audit stream to regress. The field is
  restored and now asserted field by field in the test suite rather than by
  shape, so a future omission fails loudly.

## [1.0.0] - 2026-07-29

First stable release.

### Added
- **Tamper-evident audit logging as a standalone capability.** Extracted from
  MCP Sentinel 1.13, where a hash-chained, optionally encrypted, independently
  verifiable audit trail had grown up as infrastructure for AI-agent traffic.
  It was never specific to that: personnel-record reads, permission grants,
  configuration changes and break-glass logins all want the same guarantee, and
  none of them should have to install an AI-governance module to get it —
  nor should an enterprise buyer evaluating audit posture have to work out why
  the answer is a module named after MCP.

  The chain behaviour is deliberately unchanged from that implementation: same
  canonical payload, same HMAC-SHA256-over-`prev_hash|canonical`, same
  plaintext-covered encryption model, same append lock. One addition — a
  `channel` column identifying the consumer, bound into the hash so an entry
  cannot be re-attributed to a different channel after the fact. Entries
  written without a channel keep the pre-extraction canonical form exactly, so
  rows migrated from a consumer's own table verify against their original
  hashes instead of being re-chained by the migration.

  The public contract is `AuditChainLoggerInterface`: `log()`, `verify()`,
  `decodeMetadata()` and `prune()`. `verify()` deliberately takes no channel
  argument — the chain is global, entries from every consumer are interleaved
  in one sequence, and a per-channel walk could not tell a deletion from a gap.
  A break anywhere is a break.
