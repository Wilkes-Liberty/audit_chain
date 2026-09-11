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
 * Aggregates indexed audit_chain_log columns for the reports dashboard.
 *
 * Queries are window-bounded on the indexed timestamp column and never read
 * metadata, IP addresses, user agents, or entity labels. Verification is not
 * re-run on this path: integrity() reads the last scheduled-verification
 * record from state.
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
   * Maximum distinct labels kept in a mix series before lumping the rest.
   */
  private const MIX_LIMIT = 10;

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
   * Returns a bucketed volume time series for the window.
   *
   * Buckets by hour for 24h and by day for 7d/30d. Empty buckets are filled
   * with zero so the axis is complete. An empty table in the window returns
   * an empty series so the renderer can show the empty-state.
   *
   * @param string $window
   *   One of 24h/7d/30d.
   *
   * @return array<string, int>
   *   Bucket label => count, in ascending time order.
   */
  public function volumeTimeSeries(string $window): array {
    return $this->guard(__FUNCTION__, $window, [], function () use ($window): array {
      $window = $this->normalizeWindow($window);
      $now = $this->time->getRequestTime();
      $since = $now - self::WINDOWS[$window];
      $bucketSeconds = $window === '24h' ? 3600 : 86400;

      $rows = $this->baseQuery($since)
        ->fields('l', ['timestamp'])
        ->execute();

      $counts = [];
      foreach ($rows as $row) {
        $bucket = (int) (floor(((int) $row->timestamp) / $bucketSeconds) * $bucketSeconds);
        $counts[$bucket] = ($counts[$bucket] ?? 0) + 1;
      }

      if ($counts === []) {
        return [];
      }

      $series = [];
      $start = (int) (floor($since / $bucketSeconds) * $bucketSeconds);
      for ($t = $start; $t <= $now; $t += $bucketSeconds) {
        $label = $window === '24h' ? date('H:i', $t) : date('M j', $t);
        $series[$label] = $counts[$t] ?? 0;
      }
      return $series;
    });
  }

  /**
   * Returns a count of rows by channel within the window.
   *
   * @param string $window
   *   One of 24h/7d/30d.
   *
   * @return array<string, int>
   *   Channel => count, highest first, capped with an "_other" remainder.
   */
  public function channelMix(string $window): array {
    return $this->guard(__FUNCTION__, $window, [], function () use ($window): array {
      return $this->mix($window, 'channel');
    });
  }

  /**
   * Returns a count of rows by operation within the window.
   *
   * @param string $window
   *   One of 24h/7d/30d.
   *
   * @return array<string, int>
   *   Operation => count, highest first, capped with an "_other" remainder.
   */
  public function operationMix(string $window): array {
    return $this->guard(__FUNCTION__, $window, [], function () use ($window): array {
      return $this->mix($window, 'operation');
    });
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
   * @return array{total: int, channels: int, keyed: int, unkeyed: int}
   *   Window totals. channels is the number of distinct channel values.
   */
  public function windowCounts(string $window): array {
    $empty = ['total' => 0, 'channels' => 0, 'keyed' => 0, 'unkeyed' => 0];
    return $this->guard(__FUNCTION__, $window, $empty, function () use ($window): array {
      $split = $this->keyedSplit($window);
      $since = $this->since($window);
      $channelQuery = $this->baseQuery($since);
      $channelQuery->addExpression('COUNT(DISTINCT l.channel)', 'n');
      $channels = (int) $channelQuery->execute()->fetchField();
      return [
        'total' => $split['keyed'] + $split['unkeyed'],
        'channels' => $channels,
        'keyed' => $split['keyed'],
        'unkeyed' => $split['unkeyed'],
      ];
    });
  }

  /**
   * Returns the stored scheduled-verification integrity result.
   *
   * Does not re-walk the chain. Classifies the last scheduled run the same
   * way the status report does.
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
      $run = $this->state->get(ScheduledVerifier::STATE_KEY);

      if ($interval <= 0) {
        return [
          'status' => 'warn',
          'reason' => 'disabled',
          'time' => is_array($run) ? (int) ($run['time'] ?? 0) ?: NULL : NULL,
          'rows' => $rows,
        ];
      }

      if (!is_array($run)) {
        return [
          'status' => 'warn',
          'reason' => 'pending',
          'time' => NULL,
          'rows' => $rows,
        ];
      }

      $time = (int) ($run['time'] ?? 0) ?: NULL;
      $ok = (bool) ($run['ok'] ?? FALSE);
      $reason = (string) ($run['reason'] ?? '');

      if (!$ok && $reason === AuditChainLogger::REASON_SEAL_FOREIGN) {
        return [
          'status' => 'warn',
          'reason' => 'seal_foreign',
          'time' => $time,
          'rows' => $rows,
        ];
      }

      if (!$ok) {
        return [
          'status' => 'crit',
          'reason' => 'failed',
          'time' => $time,
          'rows' => $rows,
        ];
      }

      if ($time !== NULL && $this->time->getRequestTime() > ($time + 2 * $interval)) {
        return [
          'status' => 'warn',
          'reason' => 'overdue',
          'time' => $time,
          'rows' => $rows,
        ];
      }

      return [
        'status' => 'ok',
        'reason' => 'passing',
        'time' => $time,
        'rows' => $rows,
      ];
    });
  }

  /**
   * Groups a column into a descending mix, capped with "_other".
   *
   * @param string $window
   *   One of 24h/7d/30d.
   * @param string $column
   *   An indexed varchar column on audit_chain_log.
   *
   * @return array<string, int>
   *   Label => count.
   */
  private function mix(string $window, string $column): array {
    $since = $this->since($window);
    $query = $this->baseQuery($since);
    $query->addField('l', $column, 'label');
    $query->addExpression('COUNT(*)', 'cnt');
    $query->groupBy('l.' . $column);
    $mix = [];
    foreach ($query->execute() as $row) {
      $label = (string) $row->label;
      if ($label === '') {
        $label = '_empty';
      }
      $mix[$label] = (int) $row->cnt;
    }
    arsort($mix);
    if (count($mix) <= self::MIX_LIMIT) {
      return $mix;
    }
    $top = array_slice($mix, 0, self::MIX_LIMIT, TRUE);
    $top['_other'] = (int) array_sum(array_slice($mix, self::MIX_LIMIT, NULL, TRUE));
    return $top;
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
