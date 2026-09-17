<?php

declare(strict_types=1);

namespace Drupal\audit_chain\Drush\Commands;

use Drupal\audit_chain\RecoverySegments;
use Drush\Attributes as CLI;
use Drush\Commands\AutowireTrait;
use Drush\Commands\DrushCommands;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Explicit, privileged recovery commands; never a whole-history repair.
 */
final class RecoveryCommands extends DrushCommands {

  use AutowireTrait;

  public function __construct(
    #[Autowire(service: 'audit_chain.recovery')]
    private readonly RecoverySegments $recovery,
  ) {
    parent::__construct();
  }

  /**
   * Prepare a read-only historical snapshot for operator review.
   */
  #[CLI\Command(name: 'audit-chain:recovery-prepare')]
  public function prepare(): int {
    $this->printJson($this->recovery->prepare());
    return self::EXIT_SUCCESS;
  }

  /**
   * Start a successor while retaining the historical failure.
   */
  #[CLI\Command(name: 'audit-chain:recovery-activate')]
  #[CLI\Option(name: 'segment', description: 'New segment UUID; reuse it only for identical retries.')]
  #[CLI\Option(name: 'snapshot', description: 'Exact reviewed digest from recovery-prepare.')]
  #[CLI\Option(name: 'incident', description: 'Reviewed incident reference.')]
  #[CLI\Option(name: 'reason', description: 'Reason for accepting the unresolved historical exception.')]
  #[CLI\Option(name: 'approved-by', description: 'Operator accepting that exception.')]
  #[CLI\Option(name: 'backup-digest', description: 'SHA-256 digest of the reviewed backup.')]
  #[CLI\Option(name: 'yes', description: 'Confirm the explicit historical exception without prompting.')]
  public function activate(
    array $options = [
      'segment' => '',
      'snapshot' => '',
      'incident' => '',
      'reason' => '',
      'approved-by' => '',
      'backup-digest' => '',
      'yes' => FALSE,
    ],
  ): int {
    $this->logger()->warning('This creates a separately identified successor. Historical verification remains FAILED; no original row, hash or seal is repaired.');
    if (empty($options['yes']) && !$this->io()->confirm('Activate this reviewed successor segment?', FALSE)) {
      return self::EXIT_FAILURE;
    }
    $record = $this->recovery->activate(
      (string) $options['segment'],
      (string) $options['snapshot'],
      [
        'incident' => (string) $options['incident'],
        'reason' => (string) $options['reason'],
        'approved_by' => (string) $options['approved-by'],
        'backup_digest' => (string) $options['backup-digest'],
      ],
    );
    $result = $this->recovery->verify($record['segment_id']);
    $this->printJson([
      'segment_id' => $record['segment_id'],
      'historical_ok' => FALSE,
      'verification' => $result,
    ]);
    return $result['segment_ok'] ? self::EXIT_SUCCESS : self::EXIT_FAILURE;
  }

  /**
   * Verify only an explicitly identified successor and its historical anchor.
   */
  #[CLI\Command(name: 'audit-chain:recovery-verify')]
  #[CLI\Argument(name: 'segment', description: 'The recovery segment UUID.')]
  public function verify(string $segment): int {
    $result = $this->recovery->verify($segment);
    $this->printJson($result);
    return $result['segment_ok'] ? self::EXIT_SUCCESS : self::EXIT_FAILURE;
  }

  /**
   * Export the signed recovery record with its explicit historical exception.
   */
  #[CLI\Command(name: 'audit-chain:recovery-export')]
  #[CLI\Argument(name: 'segment', description: 'The recovery segment UUID.')]
  public function export(string $segment): int {
    $result = $this->recovery->export($segment);
    $this->printJson($result);
    return $result['verification']['segment_ok'] ? self::EXIT_SUCCESS : self::EXIT_FAILURE;
  }

  /**
   * Writes a bounded recovery result without plaintext audit rows or keys.
   */
  private function printJson(array $value): void {
    $this->output()->writeln(json_encode($value, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
  }

}
