<?php

declare(strict_types=1);

namespace Drupal\audit_chain;

use Drupal\Component\Plugin\PluginManagerInterface;
use Drupal\Component\Utility\Html;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Core\Render\Markup;

/**
 * Renders a metric series as a chart render array.
 */
final class AuditChainChartRenderer {

  /**
   * Supported chart types.
   */
  private const TYPES = ['donut'];

  /**
   * SVG viewbox width used by the fallback charts.
   */
  private const SVG_WIDTH = 320;

  /**
   * SVG viewbox height used by the fallback charts.
   */
  private const SVG_HEIGHT = 160;

  /**
   * Constructs an AuditChainChartRenderer.
   *
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $moduleHandler
   *   The module handler (gates the optional drupal/charts upgrade).
   * @param \Drupal\Component\Plugin\PluginManagerInterface|null $chartsManager
   *   The Charts library plugin manager, or NULL when Charts is not installed.
   */
  public function __construct(
    private readonly ModuleHandlerInterface $moduleHandler,
    private readonly ?PluginManagerInterface $chartsManager = NULL,
  ) {}

  /**
   * Builds a render array for a metric series.
   *
   * @param string $type
   *   The chart type. Production renders donut only; unknown types fall back
   *   to donut.
   * @param array<string, int|float> $series
   *   Ordered label => value pairs.
   * @param array{title?: string} $options
   *   Optional title.
   *
   * @return array
   *   A render array: a charts element, an inline-SVG fallback, or an
   *   empty-state.
   */
  public function render(string $type, array $series, array $options = []): array {
    $type = in_array($type, self::TYPES, TRUE) ? $type : 'donut';
    $title = (string) ($options['title'] ?? '');

    if ($series === []) {
      return $this->emptyState($title);
    }

    return $this->chartsLibraryAvailable()
      ? $this->buildChartsElement($series, $title)
      : $this->buildSvgFallback($type, $series, $title);
  }

  /**
   * Builds an empty-state render array.
   *
   * @param string $title
   *   The chart title.
   *
   * @return array
   *   The empty-state build.
   */
  private function emptyState(string $title): array {
    return [
      '#prefix' => '<div class="audit-chain-chart audit-chain-chart--empty">',
      '#suffix' => '</div>',
      'title' => $this->titleElement($title),
      'empty' => [
        '#type' => 'html_tag',
        '#tag' => 'p',
        '#value' => 'No data',
        '#attributes' => ['class' => ['audit-chain-chart__empty']],
      ],
    ];
  }

  /**
   * Whether the optional Charts API can actually draw a chart.
   *
   * `charts` being enabled is not enough. Without a library plugin
   * (charts_chartjs, charts_google, charts_highcharts, …) the Charts
   * element prints "No charting library found" instead of a chart.
   *
   * @return bool
   *   TRUE when a Charts library plugin is available.
   */
  private function chartsLibraryAvailable(): bool {
    return $this->moduleHandler->moduleExists('charts')
      && $this->chartsManager instanceof PluginManagerInterface
      && $this->chartsManager->getDefinitions() !== [];
  }

  /**
   * Builds a drupal/charts `#type => 'chart'` element.
   *
   * @param array<string, int|float> $series
   *   Label => value pairs.
   * @param string $title
   *   The chart title.
   *
   * @return array
   *   A charts render element.
   */
  private function buildChartsElement(array $series, string $title): array {
    // drupal/charts uses 'pie' for donut-style splits.
    return [
      '#type' => 'chart',
      '#chart_type' => 'pie',
      '#title' => $title,
      'series' => [
        '#type' => 'chart_data',
        '#title' => $title,
        '#data' => array_values($series),
      ],
      'x_axis' => [
        '#type' => 'chart_xaxis',
        '#labels' => array_map('strval', array_keys($series)),
      ],
      'y_axis' => [
        '#type' => 'chart_yaxis',
      ],
    ];
  }

  /**
   * Builds a self-contained inline-SVG fallback (no JavaScript).
   *
   * @param string $type
   *   The chart type.
   * @param array<string, int|float> $series
   *   Label => value pairs.
   * @param string $title
   *   The chart title.
   *
   * @return array
   *   A render array containing the SVG markup.
   */
  private function buildSvgFallback(string $type, array $series, string $title): array {
    $svg = $this->donutSvg($series);
    return [
      '#prefix' => '<div class="audit-chain-chart audit-chain-chart--' . $this->escape($type) . '">',
      '#suffix' => '</div>',
      'title' => $this->titleElement($title),
      'svg' => ['#markup' => $svg],
    ];
  }

  /**
   * Builds the optional chart-title render element.
   *
   * @param string $title
   *   The title text (empty for none).
   *
   * @return array
   *   An <h4> render element, or an empty array when no title is given.
   */
  private function titleElement(string $title): array {
    if ($title === '') {
      return [];
    }
    return [
      '#type' => 'html_tag',
      '#tag' => 'h4',
      '#value' => Html::escape($title),
      '#attributes' => ['class' => ['audit-chain-chart__title']],
    ];
  }

  /**
   * Renders a donut chart as safe SVG markup.
   *
   * @param array<string, int|float> $series
   *   Label => value pairs.
   *
   * @return \Drupal\Component\Render\MarkupInterface
   *   The SVG markup.
   */
  private function donutSvg(array $series): object {
    $total = array_sum(array_map('floatval', $series));
    $cx = self::SVG_HEIGHT / 2;
    $cy = self::SVG_HEIGHT / 2;
    $r = self::SVG_HEIGHT / 2 - 8;
    $circumference = 2 * M_PI * $r;
    $offset = 0.0;
    $segments = '';
    $index = 0;
    foreach ($series as $label => $value) {
      $fraction = $total > 0 ? ((float) $value / $total) : 0.0;
      $dash = $fraction * $circumference;
      $segments .= sprintf(
        '<circle class="audit-chain-chart__slice audit-chain-chart__slice--%d" cx="%.2f" cy="%.2f" r="%.2f" fill="none" stroke-width="14" stroke-dasharray="%.2f %.2f" stroke-dashoffset="%.2f"><title>%s: %s</title></circle>',
        $index % 2, $cx, $cy, $r, $dash, $circumference - $dash, -$offset,
        $this->escape((string) $label), $this->escape((string) $value),
      );
      $offset += $dash;
      $index++;
    }
    return $this->wrapSvg($segments);
  }

  /**
   * Wraps SVG body markup in a sized, accessible <svg> element.
   *
   * @param string $body
   *   The pre-escaped inner SVG markup.
   *
   * @return \Drupal\Component\Render\MarkupInterface
   *   The full SVG markup, marked safe (all dynamic data is escaped upstream).
   */
  private function wrapSvg(string $body): object {
    $svg = sprintf(
      '<svg class="audit-chain-chart__svg" viewBox="0 0 %d %d" role="img" preserveAspectRatio="xMidYMid meet">%s</svg>',
      self::SVG_WIDTH, self::SVG_HEIGHT, $body,
    );
    // The markup is built entirely from numeric geometry plus values that have
    // already been passed through htmlspecialchars() in $this->escape(), so it
    // is safe to mark as trusted for the renderer.
    return Markup::create($svg);
  }

  /**
   * Escapes a string for safe inclusion in SVG markup.
   *
   * @param string $value
   *   The raw value.
   *
   * @return string
   *   The HTML-escaped value.
   */
  private function escape(string $value): string {
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
  }

}
