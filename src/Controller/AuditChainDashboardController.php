<?php

declare(strict_types=1);

namespace Drupal\audit_chain\Controller;

use Drupal\audit_chain\AuditChainChartRenderer;
use Drupal\audit_chain\AuditChainMetrics;
use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Datetime\DateFormatterInterface;
use Drupal\Core\Url;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Renders the Audit Chain reports dashboard.
 *
 * Does not decrypt metadata, list rows, chart volume, or re-verify the chain.
 */
final class AuditChainDashboardController extends ControllerBase {

  /**
   * The placeholder shown when a widget value cannot be computed.
   */
  private const PLACEHOLDER = '—';

  /**
   * Constructs an AuditChainDashboardController.
   *
   * @param \Drupal\audit_chain\AuditChainMetrics $metrics
   *   The dashboard-data service.
   * @param \Drupal\audit_chain\AuditChainChartRenderer $chartRenderer
   *   The chart renderer (charts + SVG fallback).
   * @param \Drupal\Core\Datetime\DateFormatterInterface $dates
   *   The date formatter (integrity card timestamps).
   * @param \Psr\Log\LoggerInterface $logger
   *   The audit_chain logger channel.
   */
  public function __construct(
    private readonly AuditChainMetrics $metrics,
    private readonly AuditChainChartRenderer $chartRenderer,
    private readonly DateFormatterInterface $dates,
    private readonly LoggerInterface $logger,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('audit_chain.metrics'),
      $container->get('audit_chain.chart_renderer'),
      $container->get('date.formatter'),
      $container->get('logger.channel.audit_chain'),
    );
  }

  /**
   * Builds the reports dashboard render array.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current request (supplies the validated ?window= query parameter).
   *
   * @return array
   *   The dashboard render array.
   */
  public function dashboard(Request $request): array {
    $window = $this->metrics->normalizeWindow((string) $request->query->get('window', AuditChainMetrics::DEFAULT_WINDOW));

    return [
      '#theme' => 'audit_chain_dashboard',
      '#chain' => $this->widget('chain', fn() => $this->buildChain(), []),
      '#recovery' => $this->widget('recovery', fn() => $this->metrics->recoveryStatus(), NULL),
      '#tiles' => $this->widget('tiles', fn() => $this->buildTiles($window), []),
      '#charts' => $this->widget('charts', fn() => $this->buildCharts($window), []),
      '#quick_actions' => $this->widget('quick_actions', fn() => $this->buildQuickActions(), []),
      '#window' => $window,
      '#windows' => $this->widget('windows', fn() => $this->buildWindowLinks($window), []),
      '#attached' => [
        'library' => ['audit_chain/dashboard'],
      ],
      '#cache' => [
        'contexts' => ['user.permissions', 'url.query_args:window'],
        // Volatile chain data; keep briefly cached. No cache tag: the logger
        // does not invalidate one on append, and a stale tag would lie.
        'max-age' => 60,
      ],
    ];
  }

  /**
   * Builds the chain-integrity card from scheduled-verification state.
   *
   * @return array{state: string, label: string, detail: string}
   *   The chain card.
   */
  private function buildChain(): array {
    $integrity = $this->metrics->integrity();
    $rows = $integrity['rows'];
    $time = $integrity['time'];
    $when = $time ? $this->dates->format($time) : self::PLACEHOLDER;

    return match ($integrity['reason']) {
      'passing' => [
        'state' => 'ok',
        'label' => (string) $this->t('Verified'),
        'detail' => (string) $this->t('@n rows. Last scheduled verification @when.', [
          '@n' => $rows,
          '@when' => $when,
        ]),
      ],
      'failed' => [
        'state' => 'crit',
        'label' => (string) $this->t('Failed'),
        'detail' => (string) $this->t('Last scheduled verification failed at @when. Run drush audit-chain:verify. The chain was not modified by the check.', [
          '@when' => $when,
        ]),
      ],
      'seal_foreign' => [
        'state' => 'warn',
        'label' => (string) $this->t('Foreign seal'),
        'detail' => (string) $this->t('Sealed prefix hashes are unchanged but this environment cannot authenticate the copied seal.'),
      ],
      'overdue' => [
        'state' => 'warn',
        'label' => (string) $this->t('Overdue'),
        'detail' => (string) $this->t('@n rows. Last successful verification @when is past twice the configured interval.', [
          '@n' => $rows,
          '@when' => $when,
        ]),
      ],
      'disabled' => [
        'state' => 'warn',
        'label' => (string) $this->t('Not scheduled'),
        'detail' => (string) $this->t('@n rows. Scheduled verification is off. Run drush audit-chain:verify, or set an interval under settings.', [
          '@n' => $rows,
        ]),
      ],
      default => [
        'state' => 'warn',
        'label' => (string) $this->t('Pending'),
        'detail' => (string) $this->t('@n rows. No scheduled verification has run yet.', [
          '@n' => $rows,
        ]),
      ],
    };
  }

  /**
   * Builds the status tiles for the windowed keyed/unkeyed split.
   *
   * @param string $window
   *   The selected window.
   *
   * @return array<int, array{label: string, value: string, sub: string, state: string}>
   *   The tile list.
   */
  private function buildTiles(string $window): array {
    $counts = $this->metrics->windowCounts($window);
    $keyedShare = $counts['total'] > 0
      ? (string) $this->t('@pct%', ['@pct' => (int) round(100 * $counts['keyed'] / $counts['total'])])
      : self::PLACEHOLDER;

    return [
      [
        'label' => (string) $this->t('Entries'),
        'value' => (string) $counts['total'],
        'sub' => (string) $this->t('in this window'),
        'state' => 'ok',
      ],
      [
        'label' => (string) $this->t('Keyed'),
        'value' => $keyedShare,
        'sub' => (string) $this->t('@n HMAC-signed', ['@n' => $counts['keyed']]),
        'state' => $counts['total'] > 0 && $counts['keyed'] === 0 ? 'warn' : 'ok',
      ],
      [
        'label' => (string) $this->t('Unkeyed'),
        'value' => (string) $counts['unkeyed'],
        'sub' => (string) $this->t('unsigned in this window'),
        'state' => $counts['unkeyed'] > 0 ? 'warn' : 'ok',
      ],
    ];
  }

  /**
   * Builds the keyed-vs-unkeyed chart.
   *
   * @param string $window
   *   The selected window.
   *
   * @return array<int, array>
   *   A single chart render array.
   */
  private function buildCharts(string $window): array {
    $split = $this->metrics->keyedSplit($window);
    $keyedSeries = ($split['keyed'] + $split['unkeyed']) > 0
      ? [
        (string) $this->t('Keyed') => $split['keyed'],
        (string) $this->t('Unkeyed') => $split['unkeyed'],
      ]
      : [];

    return [
      $this->chartRenderer->render('donut', $keyedSeries, [
        'title' => (string) $this->t('Keyed vs unkeyed'),
      ]),
    ];
  }

  /**
   * Builds the window-toggle link metadata.
   *
   * @param string $current
   *   The current window.
   *
   * @return array<int, array{key: string, label: string, url: string, active: bool}>
   *   The window links.
   */
  private function buildWindowLinks(string $current): array {
    $labels = [
      '24h' => $this->t('24 hours'),
      '7d' => $this->t('7 days'),
      '30d' => $this->t('30 days'),
    ];
    $links = [];
    foreach (AuditChainMetrics::windows() as $window) {
      $links[] = [
        'key' => $window,
        'label' => (string) $labels[$window],
        'url' => Url::fromRoute('audit_chain.dashboard', [], [
          'query' => ['window' => $window],
        ])->toString(),
        'active' => $window === $current,
      ];
    }
    return $links;
  }

  /**
   * Builds the quick-action links.
   *
   * @return array<int, array{title: string, url: string}>
   *   The action list.
   */
  private function buildQuickActions(): array {
    $actions = [];
    try {
      $actions[] = [
        'title' => (string) $this->t('Settings'),
        'url' => Url::fromRoute('audit_chain.settings')->toString(),
      ];
    }
    catch (\Throwable $e) {
      // Settings route missing would be a broken install; skip the link.
    }
    return $actions;
  }

  /**
   * Runs a widget builder, logging and degrading on failure.
   *
   * @param string $name
   *   The widget name (for the log message).
   * @param callable(): mixed $builder
   *   The widget builder.
   * @param mixed $default
   *   Value returned when the builder throws.
   *
   * @return mixed
   *   The built widget value, or $default on failure.
   */
  private function widget(string $name, callable $builder, mixed $default = NULL): mixed {
    try {
      return $builder();
    }
    catch (\Throwable $e) {
      $this->logger->error('Dashboard widget @widget failed: @message', [
        '@widget' => $name,
        '@message' => $e->getMessage(),
      ]);
      return $default;
    }
  }

}
