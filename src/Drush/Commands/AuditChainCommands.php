<?php

declare(strict_types=1);

namespace Drupal\audit_chain\Drush\Commands;

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

    $this->logger()->error(sprintf(
      'Audit chain BROKEN at row id %d. An entry has been inserted, deleted or edited since it was written.',
      (int) $result['broken_at'],
    ));
    return self::EXIT_FAILURE;
  }

}
