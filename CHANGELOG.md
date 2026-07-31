# Changelog

All notable changes to Audit Chain are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
