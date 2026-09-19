<?php

declare(strict_types=1);

namespace Drupal\audit_chain_mcp\Plugin\tool\Tool;

use Drupal\audit_chain\ScheduledVerifier;
use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\State\StateInterface;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\tool\Attribute\Tool;
use Drupal\tool\Tool\ToolOperation;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Runs scheduled verification now.
 */
#[Tool(
  id: 'audit_chain_verify_now',
  label: new TranslatableMarkup('Verify the audit chain now'),
  description: new TranslatableMarkup('Run the scheduled chain verification now and return its verdict. Expensive: verification reads every row past the seal and decrypts its metadata, so the cost grows with the table. The profile rate limit applies, and a call within 60 seconds of the last recorded run returns that run with "ran": false instead of walking the table again. The run is recorded exactly as a cron run is: a failure is logged and the verification-failed event fires. Verification never changes the chain. Returns verdict fields only: no rows, metadata, hashes or key identifiers. "broken_at" is a row id.'),
  operation: ToolOperation::Trigger,
  input_definitions: [],
)]
final class VerifyNowTool extends AuditChainToolBase {

  /**
   * Seconds within which a recorded run is returned instead of a new walk.
   *
   * A tightening on top of the profile rate limit, which counts calls and
   * knows nothing about what one call costs here.
   */
  private const MIN_INTERVAL = 60;

  /**
   * Scheduled verifier.
   */
  protected ScheduledVerifier $verifier;

  /**
   * State, for the last recorded run.
   */
  protected StateInterface $state;

  /**
   * Time service.
   */
  protected TimeInterface $time;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->verifier = $container->get('audit_chain.scheduled_verifier');
    $instance->state = $container->get('state');
    $instance->time = $container->get('datetime.time');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  protected function extraPermissions(): array {
    return ['run audit chain verification via mcp'];
  }

  /**
   * {@inheritdoc}
   */
  protected function run(array $values): array {
    $last = $this->state->get(ScheduledVerifier::STATE_KEY);
    $age = is_array($last) ? $this->time->getCurrentTime() - (int) ($last['time'] ?? 0) : NULL;
    $ran = $age === NULL || $age < 0 || $age >= self::MIN_INTERVAL;
    $run = $ran ? $this->verifier->runNow() : $last;
    if ($ran) {
      $this->logger->info('Ran Audit Chain verification through MCP for uid @uid.', [
        '@uid' => (int) $this->currentUser->id(),
      ]);
    }
    return ['ran' => $ran]
      + (array) $this->verdictFields($run)
      + ['successor' => $this->successorFields($run['successor'] ?? NULL)];
  }

}
