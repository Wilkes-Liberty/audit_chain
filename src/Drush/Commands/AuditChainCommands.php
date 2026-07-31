<?php

declare(strict_types=1);

namespace Drupal\audit_chain\Drush\Commands;

use Drupal\audit_chain\AuditChainLogger;
use Drupal\audit_chain\AuditChainLoggerInterface;
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
      $this->logger()->success(sprintf('Audit chain OK — %d entries verified.', $rows));
      return self::EXIT_SUCCESS;
    }

    // Still a non-zero exit: a chain the site believes is signed and is not is
    // a real finding, and the exit code is the documented contract that
    // monitoring keys on. What changes is the diagnosis — telling an operator
    // their audit log has been edited when in fact their signing key was
    // missing sends them hunting for an intruder who does not exist.
    if ($result['reason'] === AuditChainLogger::REASON_WRITTEN_UNKEYED) {
      $this->logger()->error(sprintf(
        'Audit chain UNSIGNED — %d of %d entries (through row id %d) were hashed without the configured signing key. '
        . 'The chain is internally consistent and nothing has been edited; it simply is not signed through there, '
        . 'so those rows can be rewritten by anyone with database access. '
        . 'This usually means the Key entity did not resolve in the environment that wrote them. '
        . 'Entries already written cannot be signed retrospectively.',
        (int) $result['unkeyed_rows'],
        $rows,
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

}
