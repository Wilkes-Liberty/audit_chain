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
 * recordedGaps() is the exception: it decrypts chain_gap_recorded rows and
 * returns the fork and lost range only. Verification is not re-run on this
 * path: snapshot() reads the last scheduled-verification record from state
 * and assembles it with ScheduledVerificationPresentation::snapshot().
 * classify() remains the only classifier. integrity() projects the
 * classified fields and row count from that snapshot.
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
   * @param \Drupal\audit_chain\ChainGap|null $gaps
   *   Recorded-gap listing. NULL in tests that build metrics by hand.
   */
  public function __construct(
    private readonly Connection $database,
    private readonly TimeInterface $time,
    private readonly StateInterface $state,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly LoggerInterface $logger,
    private readonly ?ChainGap $gaps = NULL,
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
   * ScheduledVerificationIntegrity::classify() via snapshot().
   *
   * @return array{status: string, reason: string, time: int|null, rows: int}
   *   status is ok/warn/crit. reason is a stable machine key.
   */
  public function integrity(): array {
    $snapshot = $this->snapshot();
    return [
      'status' => $snapshot['classified']['status'],
      'reason' => $snapshot['classified']['reason'],
      'time' => $snapshot['classified']['time'],
      'rows' => $snapshot['rows'],
    ];
  }

  /**
   * Returns one scheduled-verification snapshot for operator surfaces.
   *
   * Does not re-walk the chain. classify() remains the only classifier.
   * Callers that interpolate last-run time pass a formatter; the scheduled
   * verifier passes extra.when as DATE_ATOM instead.
   *
   * @param callable|null $formatWhen
   *   (optional) Formats classified last-run time. Unused when the
   *   classified state has no last-run time (disabled/pending).
   *
   * @return array
   *   classified, rows, run, when, context, and presented.
   *
   * @phpstan-param (callable(int): string)|null $formatWhen
   */
  public function snapshot(?callable $formatWhen = NULL): array {
    $loaded = $this->loadScheduledVerification();
    return ScheduledVerificationPresentation::snapshot(
      $loaded['run'],
      $loaded['interval'],
      $loaded['now'],
      [
        'rows' => $loaded['rows'],
        'require_keyed' => $loaded['require_keyed'],
      ],
      $formatWhen,
    );
  }

  /**
   * Lists recorded gaps for the dashboard.
   *
   * Decrypts only chain_gap_recorded rows. Other metadata is not read.
   *
   * @return list<array{row_id: int, readable: bool, fork_id: int|null, lost_from_id: int|null, lost_through_id: int|null, lost_count: int|null}>
   *   One entry per gap row, or an empty list when the reader is absent.
   */
  public function recordedGaps(): array {
    $gaps = $this->gaps;
    if ($gaps === NULL) {
      return [];
    }
    $listed = $this->guard('recordedGaps', NULL, [], fn (): array => $gaps->recorded());
    return is_array($listed) ? $listed : [];
  }

  /**
   * Reads the scheduled successor result without re-verifying on page load.
   */
  public function recoveryStatus(): ?array {
    $run = $this->state->get(ScheduledVerifier::STATE_KEY);
    return is_array($run) && is_array($run['successor'] ?? NULL) ? $run['successor'] : NULL;
  }

  /**
   * Loads the stored run, interval, and live row count once per request.
   *
   * A thrown query degrades to pending: interval 1 with no run, matching
   * the previous integrity() fallback.
   *
   * @return array
   *   Inputs for ScheduledVerificationPresentation::snapshot().
   *
   * @phpstan-return array{
   *   run: mixed,
   *   interval: int,
   *   now: int,
   *   rows: int,
   *   require_keyed: bool
   * }
   */
  private function loadScheduledVerification(): array {
    $fallback = [
      'run' => NULL,
      'interval' => 1,
      'now' => $this->time->getRequestTime(),
      'rows' => 0,
      'require_keyed' => FALSE,
    ];
    return $this->guard(__FUNCTION__, NULL, $fallback, function (): array {
      $rows = 0;
      if ($this->database->schema()->tableExists('audit_chain_log')) {
        $rows = (int) $this->database->select('audit_chain_log', 'l')
          ->countQuery()
          ->execute()
          ->fetchField();
      }
      $settings = $this->configFactory->get('audit_chain.settings');
      return [
        'run' => $this->state->get(ScheduledVerifier::STATE_KEY),
        'interval' => (int) $settings->get('verify_interval'),
        'now' => $this->time->getRequestTime(),
        'rows' => $rows,
        'require_keyed' => (bool) $settings->get('verify_require_keyed'),
      ];
    });
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
