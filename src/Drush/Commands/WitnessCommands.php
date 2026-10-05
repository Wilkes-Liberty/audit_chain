<?php

declare(strict_types=1);

namespace Drupal\audit_chain\Drush\Commands;

use Drupal\audit_chain\WitnessOperator;
use Drush\Attributes as CLI;
use Drush\Commands\AutowireTrait;
use Drush\Commands\DrushCommands;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Witness commands.
 *
 * Submission requires the operator to repeat the persisted digest and the
 * exact backend list. Drush's affirmative flag is not an approval. These
 * commands do not wait for Bitcoin and do not submit from cron, routes, or
 * hooks.
 */
final class WitnessCommands extends DrushCommands {

  use AutowireTrait;

  public function __construct(
    #[Autowire(service: 'audit_chain.witness_operator')]
    private readonly WitnessOperator $operator,
  ) {
    parent::__construct();
  }

  /**
   * Submit a persisted checkpoint digest to named witness backends.
   */
  #[CLI\Command(name: 'audit-chain:witness-submit')]
  #[CLI\Option(name: 'digest', description: 'Persisted checkpoint digest.')]
  #[CLI\Option(name: 'backends', description: 'Comma-separated backend ids.')]
  #[CLI\Option(name: 'confirm-digest', description: 'Repeat the persisted digest.')]
  #[CLI\Option(name: 'confirm-backends', description: 'Repeat the backend list.')]
  #[CLI\Option(name: 'new-attempt', description: 'Store another receipt instead of reusing one.')]
  public function submit(
    array $options = [
      'digest' => '',
      'backends' => '',
      'confirm-digest' => '',
      'confirm-backends' => '',
      'new-attempt' => FALSE,
    ],
  ): int {
    $result = $this->operator->submit(
      (string) $options['digest'],
      (string) $options['backends'],
      (string) $options['confirm-digest'],
      (string) $options['confirm-backends'],
      (bool) $options['new-attempt'],
    );
    $this->printLines($result->lines);
    return $result->exitCode === 0 ? self::EXIT_SUCCESS : self::EXIT_FAILURE;
  }

  /**
   * Advance one witness receipt a single step.
   */
  #[CLI\Command(name: 'audit-chain:witness-upgrade')]
  #[CLI\Option(name: 'receipt', description: 'Witness receipt id.')]
  public function upgrade(array $options = ['receipt' => '']): int {
    $result = $this->operator->upgrade((string) $options['receipt']);
    $this->printLines($result->lines);
    return $result->exitCode === 0 ? self::EXIT_SUCCESS : self::EXIT_FAILURE;
  }

  /**
   * Verify one witness receipt. Non-zero means it is not valid.
   */
  #[CLI\Command(name: 'audit-chain:witness-verify')]
  #[CLI\Option(name: 'receipt', description: 'Witness receipt id.')]
  #[CLI\Option(name: 'digest', description: 'Persisted checkpoint digest.')]
  public function verify(
    array $options = [
      'receipt' => '',
      'digest' => '',
    ],
  ): int {
    $result = $this->operator->verify((string) $options['receipt'], (string) $options['digest']);
    $this->printLines($result->lines);
    return $result->exitCode === 0 ? self::EXIT_SUCCESS : self::EXIT_FAILURE;
  }

  /**
   * List witness receipt ids for a checkpoint.
   */
  #[CLI\Command(name: 'audit-chain:witness-receipts')]
  #[CLI\Option(name: 'digest', description: 'Persisted checkpoint digest.')]
  public function receipts(array $options = ['digest' => '']): int {
    $result = $this->operator->receipts((string) $options['digest']);
    $this->printLines($result->lines);
    return $result->exitCode === 0 ? self::EXIT_SUCCESS : self::EXIT_FAILURE;
  }

  /**
   * Show each witness receipt and its own fresh verdict.
   */
  #[CLI\Command(name: 'audit-chain:witness-status')]
  #[CLI\Option(name: 'digest', description: 'Persisted checkpoint digest.')]
  #[CLI\Option(name: 'require', description: 'opentimestamps, xrpl, or all. Empty prints only.')]
  public function status(
    array $options = [
      'digest' => '',
      'require' => '',
    ],
  ): int {
    $result = $this->operator->status((string) $options['digest'], (string) $options['require']);
    $this->printLines($result->lines);
    return $result->exitCode === 0 ? self::EXIT_SUCCESS : self::EXIT_FAILURE;
  }

  /**
   * Write portable witness bytes for one receipt.
   */
  #[CLI\Command(name: 'audit-chain:witness-export')]
  #[CLI\Option(name: 'receipt', description: 'Witness receipt id.')]
  public function export(array $options = ['receipt' => '']): int {
    $result = $this->operator->export((string) $options['receipt']);
    if ($result->bytes === NULL) {
      $this->printLines($result->lines);
      return self::EXIT_FAILURE;
    }
    $this->output()->write($result->bytes);
    return self::EXIT_SUCCESS;
  }

  /**
   * Prints command lines.
   *
   * @param list<string> $lines
   *   Lines returned by the operator.
   */
  private function printLines(array $lines): void {
    foreach ($lines as $line) {
      $this->output()->writeln($line);
    }
  }

}
