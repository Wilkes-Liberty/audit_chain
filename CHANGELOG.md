# Changelog

All notable changes to Audit Chain are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
