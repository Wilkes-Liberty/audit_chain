<?php

declare(strict_types=1);

namespace Drupal\audit_chain\Drush\Commands;

use Drupal\audit_chain\WitnessDemo;
use Drush\Attributes as CLI;
use Drush\Commands\AutowireTrait;
use Drush\Commands\DrushCommands;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Controlled-environment witness demo.
 *
 * These commands do nothing unless settings.php sets
 * audit_chain_witness_demo to TRUE. They do not change the shipped empty
 * witness_backend default and they do not sign XRPL payments.
 */
final class WitnessDemoCommands extends DrushCommands {

  use AutowireTrait;

  public function __construct(
    #[Autowire(service: 'audit_chain.witness_demo')]
    private readonly WitnessDemo $demo,
  ) {
    parent::__construct();
  }

  /**
   * Walk one demo step, or the full mocked-safe sequence with run.
   */
  #[CLI\Command(name: 'audit-chain:witness-demo')]
  #[CLI\Argument(name: 'step', description: 'prepare, checkpoint, submit, status, upgrade, verify, tamper, reset, or run.')]
  #[CLI\Option(name: 'digest', description: 'Checkpoint digest. Empty uses the last demo digest.')]
  #[CLI\Usage(name: 'drush audit-chain:witness-demo prepare', description: 'Copy testnet relay settings into site config.')]
  #[CLI\Usage(name: 'drush audit-chain:witness-demo run', description: 'Walk prepare through tamper.')]
  public function demo(
    string $step = 'status',
    array $options = ['digest' => ''],
  ): int {
    $result = $this->demo->step($step, (string) $options['digest']);
    foreach ($result->lines as $line) {
      $this->output()->writeln($line);
    }
    return $result->exitCode === 0 ? self::EXIT_SUCCESS : self::EXIT_FAILURE;
  }

}
