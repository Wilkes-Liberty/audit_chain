<?php

declare(strict_types=1);

namespace Drupal\audit_chain\Drush\Commands;

use Drupal\audit_chain\AuditChainLogger;
use Drupal\audit_chain\AuditChainLoggerInterface;
use Drupal\audit_chain\EvidenceExporter;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drush\Attributes as CLI;
use Drush\Commands\AutowireTrait;
use Drush\Commands\DrushCommands;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Verification and inspection commands for the audit chain.
 *
 * The exit code is the contract: a non-zero status from audit-chain:verify
 * means the chain does not verify, so it can be wired straight into monitoring
 * or a deploy gate without parsing output.
 */
final class AuditChainCommands extends DrushCommands {

  use AutowireTrait;

  /**
   * Constructs an AuditChainCommands object.
   */
  public function __construct(
    #[Autowire(service: 'audit_chain.logger')]
    private readonly AuditChainLoggerInterface $auditChain,
    #[Autowire(service: 'database')]
    private readonly Connection $database,
    #[Autowire(service: 'audit_chain.evidence_exporter')]
    private readonly EvidenceExporter $evidenceExporter,
    #[Autowire(service: 'config.factory')]
    private readonly ConfigFactoryInterface $configFactory,
  ) {
    parent::__construct();
  }

  /**
   * Verify the tamper-evident audit chain.
   */
  #[CLI\Command(name: 'audit-chain:verify', aliases: ['acv'])]
  #[CLI\Usage(name: 'drush audit-chain:verify', description: 'Walk every entry and verify the hash chain.')]
  public function verify(): int {
    $rows = (int) $this->database->select('audit_chain_log', 'l')
      ->countQuery()
      ->execute()
      ->fetchField();

    $result = $this->auditChain->verify();

    if ($result['ok']) {
      if (!empty($result['sealed_through'])) {
        $this->logger()->success(sprintf(
          'Audit chain OK — sealed through row id %d; content verified from row id %s (%d total entries).',
          (int) $result['sealed_through'],
          $result['verified_from'] !== NULL ? (string) $result['verified_from'] : '(none post-seal)',
          $rows,
        ));
      }
      else {
        $this->logger()->success(sprintf('Audit chain OK — %d entries verified.', $rows));
      }
      return self::EXIT_SUCCESS;
    }

    // Still a non-zero exit: a chain the site believes is signed and is not is
    // a real finding, and the exit code is the documented contract that
    // monitoring keys on. What changes is the diagnosis — telling an operator
    // their audit log has been edited when in fact their signing key was
    // missing sends them hunting for an intruder who does not exist.
    if ($result['reason'] === AuditChainLogger::REASON_SEAL_FOREIGN) {
      $this->logger()->warning(sprintf(
        'Audit chain SEAL FOREIGN — the stored hashes in the sealed prefix through row id %d still match its digest, '
        . 'but this environment cannot authenticate the seal MAC with a current or retired signing key. '
        . 'No sealed hash change was detected. Verify on the source environment, or configure its signing key as retired only if policy permits. '
        . 'This copy remains unverified and evidence export stays blocked.',
        (int) ($result['sealed_through'] ?? 0),
      ));
      return self::EXIT_FAILURE;
    }

    if ($result['reason'] === AuditChainLogger::REASON_SEAL_BROKEN) {
      $this->logger()->error(sprintf(
        'Audit chain SEAL BROKEN — the sealed prefix through row id %d has changed since it was sealed '
        . '(stored row_hash values no longer match the seal digest). '
        . 'That is tampering of historical evidence, not an ordinary rotation.',
        (int) ($result['sealed_through'] ?? 0),
      ));
      return self::EXIT_FAILURE;
    }

    if ($result['reason'] === AuditChainLogger::REASON_WRITTEN_UNKEYED) {
      $this->logger()->error(sprintf(
        'Audit chain UNSIGNED — %d of %d entries (through row id %d) were hashed without the configured signing key. '
        . 'The chain is internally consistent and nothing has been edited; it simply is not signed through there, '
        . 'so those rows can be rewritten by anyone with database access. '
        . 'This usually means the Key entity did not resolve in the environment that wrote them. '
        . 'Entries already written cannot be signed retrospectively. '
        . 'To mark a historical unkeyed prefix without re-chaining, use: drush audit-chain:seal --through=%d --reason="…".',
        (int) $result['unkeyed_rows'],
        $rows,
        (int) $result['unkeyed_through'],
        (int) $result['unkeyed_through'],
      ));
      return self::EXIT_FAILURE;
    }

    $this->logger()->error(sprintf(
      'Audit chain BROKEN at row id %d. An entry has been inserted, deleted or edited since it was written.',
      (int) $result['broken_at'],
    ));
    return self::EXIT_FAILURE;
  }

  /**
   * Seal an unverifiable prefix (do not re-chain).
   *
   * Only covers rows that do not verify under the configured signing keys.
   * Records a keyed digest over stored hashes so future edits stay detectable.
   */
  #[CLI\Command(name: 'audit-chain:seal', aliases: ['acs'])]
  #[CLI\Option(name: 'through', description: 'Highest row id to include in the seal (inclusive).')]
  #[CLI\Option(name: 'reason', description: 'Operator reason (required; stored on the seal and in the audit entry).')]
  #[CLI\Option(name: 'yes', description: 'Skip confirmation.')]
  #[CLI\Usage(name: 'drush audit-chain:seal --through=1997 --reason="pre-key unkeyed production segment"', description: 'Seal rows 1..1997.')]
  public function seal(
    array $options = ['through' => 0, 'reason' => '', 'yes' => FALSE],
  ): int {
    $through = (int) ($options['through'] ?? 0);
    $reason = (string) ($options['reason'] ?? '');
    if ($through < 1 || $reason === '') {
      $this->logger()->error('Both --through=<id> and --reason="…" are required.');
      return self::EXIT_FAILURE;
    }

    if (empty($options['yes'])) {
      $this->logger()->warning(sprintf(
        'Sealing through row %d is permanent site state. Post-seal verification will not re-check that prefix\'s content — only that its stored hashes are unchanged. Continue only if you accept that history as frozen.',
        $through,
      ));
      if (!$this->io()->confirm('Seal this prefix?', FALSE)) {
        $this->logger()->notice('Aborted.');
        return self::EXIT_FAILURE;
      }
    }

    $result = $this->auditChain->sealPrefix($through, $reason);
    if (!$result['sealed']) {
      $this->logger()->error($result['message']);
      return self::EXIT_FAILURE;
    }
    $this->logger()->success($result['message']);
    return self::EXIT_SUCCESS;
  }

  /**
   * Re-encrypt audit metadata from one EncryptionProfile to another.
   *
   * Does not touch row hashes. Safe to re-run: only rows still on --from are
   * rewritten. Run until remaining is 0 when using --limit batches.
   */
  #[CLI\Command(name: 'audit-chain:reencrypt', aliases: ['acre'])]
  #[CLI\Option(name: 'from', description: 'Source encryption profile id (rows with this encryption_profile).')]
  #[CLI\Option(name: 'to', description: 'Destination encryption profile id.')]
  #[CLI\Option(name: 'limit', description: 'Max rows per run (0 = all). Use for resumable batches.')]
  #[CLI\Usage(name: 'drush audit-chain:reencrypt --from=old_profile --to=new_profile', description: 'Re-encrypt every row still on old_profile.')]
  #[CLI\Usage(name: 'drush audit-chain:reencrypt --from=old_profile --to=new_profile --limit=500', description: 'Re-encrypt the next 500 rows.')]
  public function reencrypt(
    array $options = ['from' => '', 'to' => '', 'limit' => 0],
  ): int {
    $from = (string) ($options['from'] ?? '');
    $to = (string) ($options['to'] ?? '');
    $limit = (int) ($options['limit'] ?? 0);
    if ($from === '' || $to === '') {
      $this->logger()->error('Both --from and --to encryption profile ids are required.');
      return self::EXIT_FAILURE;
    }

    $result = $this->auditChain->reencrypt($from, $to, $limit);
    if ($result['refused'] !== NULL) {
      $this->logger()->error($result['refused']);
      return self::EXIT_FAILURE;
    }

    $this->logger()->success(sprintf(
      'Re-encrypted %d row(s); %d failed; %d still on source profile "%s".',
      $result['updated'],
      $result['failed'],
      $result['remaining'],
      $from,
    ));
    if ($result['failed'] > 0) {
      return self::EXIT_FAILURE;
    }
    return self::EXIT_SUCCESS;
  }

  /**
   * Export chain rows to an off-system evidence destination.
   *
   * Delivery is at-least-once: the per-destination checkpoint advances only
   * after a delivery succeeds, so re-running after a failure retries the same
   * rows and consumers must deduplicate on the row id. Export refuses while
   * the last scheduled verification is failing.
   */
  #[CLI\Command(name: 'audit-chain:export', aliases: ['ace'])]
  #[CLI\Option(name: 'destination', description: 'http(s) ingest URL or file path. Defaults to the configured export_destination.')]
  #[CLI\Option(name: 'from-id', description: 'Replay from this row id instead of the checkpoint (the checkpoint never moves backwards).')]
  #[CLI\Option(name: 'channel', description: 'Restrict the export to one channel partition.')]
  #[CLI\Option(name: 'limit', description: 'Max rows this run (0 = all). Checkpointing makes limited runs resumable.')]
  #[CLI\Usage(name: 'drush audit-chain:export --destination=https://evidence.example.com/ingest', description: 'Push new rows since the checkpoint.')]
  #[CLI\Usage(name: 'drush audit-chain:export --destination=/var/evidence/chain.ndjson --from-id=1', description: 'Replay the full history to a file.')]
  public function export(
    array $options = ['destination' => '', 'from-id' => 0, 'channel' => '', 'limit' => 0],
  ): int {
    $destination = (string) ($options['destination'] ?? '');
    if ($destination === '') {
      $destination = (string) $this->configFactory->get('audit_chain.settings')->get('export_destination');
    }
    if ($destination === '') {
      $this->logger()->error('No destination: pass --destination or configure export_destination.');
      return self::EXIT_FAILURE;
    }
    $fromId = (int) ($options['from-id'] ?? 0);
    $channel = (string) ($options['channel'] ?? '');
    $limit = (int) ($options['limit'] ?? 0);

    $run = $this->evidenceExporter->exportTo(
      $destination,
      $fromId > 0 ? $fromId : NULL,
      $channel === '' ? NULL : $channel,
      $limit > 0 ? $limit : NULL,
    );

    if (!$run['ok']) {
      $this->logger()->error(sprintf(
        'Export failed (%s); the checkpoint is unchanged and a re-run retries the same rows.',
        (string) $run['reason'],
      ));
      return self::EXIT_FAILURE;
    }
    $this->logger()->success(sprintf(
      'Delivered %d row(s)%s to %s; %d remaining beyond the checkpoint.',
      $run['delivered'],
      $run['last_id'] !== NULL ? sprintf(' (through id %d)', $run['last_id']) : '',
      EvidenceExporter::redactDestination($destination),
      $run['remaining'],
    ));
    return self::EXIT_SUCCESS;
  }

}
