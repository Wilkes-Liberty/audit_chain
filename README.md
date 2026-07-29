# Audit Chain

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

## Two constraints every consumer must respect

**1. Do not log per access check.** A hook like `hook_entity_field_access()`
fires per field, per entity, per render. Writing an entry each time produces a
chain nobody can read and a write-amplified request — the log stops being
evidence and becomes noise. Dedupe per request and flush once:

```php
// Collect during the request…
$this->pending[$entityType . ':' . $id . ':' . $field] = TRUE;

// …and write once, on kernel.terminate.
public static function getSubscribedEvents(): array {
  return [KernelEvents::TERMINATE => ['flush', 0]];
}
```

**2. Rotating the encryption profile orphans existing entries.** Metadata
encrypted under profile A cannot be decrypted after switching to profile B, and
the chain is computed over the *plaintext* — so those entries stop verifying,
and the failure looks exactly like tampering. Export or re-encrypt before
rotating. The settings form says so at the point of change, but it cannot stop
you.

## Configuration

**Configuration → System → Audit Chain** (`/admin/config/system/audit-chain`).

| Setting | Effect |
|---------|--------|
| Signing key | A Key entity. Empty means plain SHA-256 — enough to detect accidental corruption and careless edits, not enough to stop someone with database access recomputing the chain. Store the key outside the database (File or Environment provider). |
| Encryption profile | Encrypts `metadata` at rest. See the rotation caveat above. |
| Stream entries | Emits each entry to the `audit_chain` logger channel as a structured record, so syslog or Monolog can forward to a SIEM without polling. |

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

- Jeremy Michael Cerda — <jmcerda@wilkesliberty.com>
- Wilkes & Liberty, LLC — [drupal.org/u/wilkes-liberty](https://www.drupal.org/u/wilkes-liberty)
