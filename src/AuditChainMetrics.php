<?php

declare(strict_types=1);

namespace Drupal\audit_chain;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Database\Query\SelectInterface;
use Drupal\Core\State\StateInterface;
use Psr\Log\LoggerInterface;

/**
 * Integrity and keyed/unkeyed counts for the reports dashboard.
 *
 * Queries are window-bounded on the indexed timestamp and key_id columns and
 * never read metadata, IP addresses, user agents, or entity labels.
 * Verification is not re-run on this path: integrity() reads the last
 * scheduled-verification record from state and classifies it with
 * ScheduledVerificationIntegrity.
 */
final class AuditChainMetrics {

  /**
   * Allowlisted dashboard windows mapped to their length in seconds.
   */
  private const WINDOWS = [
    '24h' => 86400,
    '7d' => 604800,
    '30d' => 2592000,
  ];

  /**
   * The default window used when an unknown value is supplied.
   */
  public const DEFAULT_WINDOW = '24h';

  /**
   * Per-request static result cache, keyed by "method:window".
   *
   * @var array<string, mixed>
   */
  private array $staticCache = [];

  /**
   * Constructs an AuditChainMetrics.
   *
   * @param \Drupal\Core\Database\Connection $database
   *   The database connection.
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   The time service.
   * @param \Drupal\Core\State\StateInterface $state
   *   The state service (scheduled verification record).
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory (verify_interval).
   * @param \Psr\Log\LoggerInterface $logger
   *   The audit_chain logger channel.
   */
  public function __construct(
    private readonly Connection $database,
    private readonly TimeInterface $time,
    private readonly StateInterface $state,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly LoggerInterface $logger,
  ) {}

  /**
   * Returns the allowlisted window keys.
   *
   * @return list<string>
   *   The window keys in display order.
   */
  public static function windows(): array {
    return array_keys(self::WINDOWS);
  }

  /**
   * Normalizes a window key against the allowlist.
   *
   * @param string $window
   *   A requested window.
   *
   * @return string
   *   A guaranteed-valid window key.
   */
  public function normalizeWindow(string $window): string {
    return isset(self::WINDOWS[$window]) ? $window : self::DEFAULT_WINDOW;
  }

  /**
   * Returns keyed vs unkeyed row counts within the window.
   *
   * A row is keyed when key_id is a non-empty string. NULL and '' are unkeyed
   * (including historical rows written before the column existed).
   *
   * @param string $window
   *   One of 24h/7d/30d.
   *
   * @return array{keyed: int, unkeyed: int}
   *   The split. Both zero when the window is empty.
   */
  public function keyedSplit(string $window): array {
    $empty = ['keyed' => 0, 'unkeyed' => 0];
    return $this->guard(__FUNCTION__, $window, $empty, function () use ($window, $empty): array {
      $since = $this->since($window);
      $total = (int) $this->baseQuery($since)
        ->countQuery()
        ->execute()
        ->fetchField();
      if ($total === 0) {
        return $empty;
      }
      $keyedQuery = $this->baseQuery($since);
      $keyedQuery->isNotNull('l.key_id');
      $keyedQuery->condition('l.key_id', '', '<>');
      $keyed = (int) $keyedQuery->countQuery()->execute()->fetchField();
      return [
        'keyed' => $keyed,
        'unkeyed' => max($total - $keyed, 0),
      ];
    });
  }

  /**
   * Returns headline counts for the window.
   *
   * @param string $window
   *   One of 24h/7d/30d.
   *
   * @return array{total: int, keyed: int, unkeyed: int}
   *   Window totals for the keyed/unkeyed split.
   */
  public function windowCounts(string $window): array {
    $empty = ['total' => 0, 'keyed' => 0, 'unkeyed' => 0];
    return $this->guard(__FUNCTION__, $window, $empty, function () use ($window): array {
      $split = $this->keyedSplit($window);
      return [
        'total' => $split['keyed'] + $split['unkeyed'],
        'keyed' => $split['keyed'],
        'unkeyed' => $split['unkeyed'],
      ];
    });
  }

  /**
   * Returns the stored scheduled-verification integrity result.
   *
   * Does not re-walk the chain. Classification is
   * ScheduledVerificationIntegrity::classify(); this method adds the row count.
   *
   * @return array{status: string, reason: string, time: int|null, rows: int}
   *   status is ok/warn/crit. reason is a stable machine key.
   */
  public function integrity(): array {
    $fallback = [
      'status' => 'warn',
      'reason' => 'pending',
      'time' => NULL,
      'rows' => 0,
    ];
    return $this->guard(__FUNCTION__, NULL, $fallback, function (): array {
      $rows = 0;
      if ($this->database->schema()->tableExists('audit_chain_log')) {
        $rows = (int) $this->database->select('audit_chain_log', 'l')
          ->countQuery()
          ->execute()
          ->fetchField();
      }

      $interval = (int) $this->configFactory->get('audit_chain.settings')->get('verify_interval');
      $classified = ScheduledVerificationIntegrity::classify(
        $this->state->get(ScheduledVerifier::STATE_KEY),
        $interval,
        $this->time->getRequestTime(),
      );
      return [
        'status' => $classified['status'],
        'reason' => $classified['reason'],
        'time' => $classified['time'],
        'rows' => $rows,
      ];
    });
  }

  /**
   * Reads the scheduled successor result without re-verifying on page load.
   */
  public function recoveryStatus(): ?array {
    $run = $this->state->get(ScheduledVerifier::STATE_KEY);
    return is_array($run) && is_array($run['successor'] ?? NULL) ? $run['successor'] : NULL;
  }

  /**
   * Returns the unix timestamp at the start of the window.
   *
   * @param string $window
   *   A requested window.
   *
   * @return int
   *   Seconds since epoch.
   */
  private function since(string $window): int {
    $window = $this->normalizeWindow($window);
    return $this->time->getRequestTime() - self::WINDOWS[$window];
  }

  /**
   * Builds a timestamp-bounded select against audit_chain_log.
   *
   * @param int $since
   *   Inclusive unix timestamp lower bound.
   *
   * @return \Drupal\Core\Database\Query\SelectInterface
   *   The query.
   */
  private function baseQuery(int $since): SelectInterface {
    return $this->database->select('audit_chain_log', 'l')
      ->condition('l.timestamp', $since, '>=');
  }

  /**
   * Runs a metric builder, logging and degrading on failure.
   *
   * @param string $method
   *   The calling method name (cache key).
   * @param string|null $window
   *   The window, or NULL when the metric is windowless.
   * @param mixed $default
   *   Value returned when the builder throws.
   * @param callable(): mixed $builder
   *   The metric builder.
   *
   * @return mixed
   *   The built value, or $default on failure.
   */
  private function guard(string $method, ?string $window, mixed $default, callable $builder): mixed {
    $key = $method . ':' . ($window ?? '');
    if (array_key_exists($key, $this->staticCache)) {
      return $this->staticCache[$key];
    }
    try {
      $this->staticCache[$key] = $builder();
    }
    catch (\Throwable $e) {
      $this->logger->error('Dashboard metric @metric failed: @message', [
        '@metric' => $method,
        '@message' => $e->getMessage(),
      ]);
      $this->staticCache[$key] = $default;
    }
    return $this->staticCache[$key];
  }

}
