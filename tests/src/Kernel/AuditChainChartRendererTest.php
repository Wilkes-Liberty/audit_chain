<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain\Kernel;

use Drupal\audit_chain\AuditChainChartRenderer;
use Drupal\Component\Plugin\PluginManagerInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\KernelTests\KernelTestBase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel tests for the chart renderer helper.
 *
 * This class runs WITHOUT the contrib 'charts' module, so it exercises the
 * inline-SVG fallback and empty-state branches. The drupal/charts branch is
 * asserted in an optional, skip-guarded test when the module is installed.
 *
 * @coversDefaultClass \Drupal\audit_chain\AuditChainChartRenderer
 *
 * @group audit_chain
 *
 * @runTestsInSeparateProcesses
 */
#[CoversClass(AuditChainChartRenderer::class)]
#[Group('audit_chain')]
#[RunTestsInSeparateProcesses]
final class AuditChainChartRendererTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system',
    'user',
    'key',
    'encrypt',
    'encrypt_test',
    'audit_chain',
  ];

  /**
   * @covers ::render
   */
  public function testFallbackReturnsInlineSvgWhenChartsAbsent(): void {
    /** @var \Drupal\audit_chain\AuditChainChartRenderer $r */
    $r = \Drupal::service('audit_chain.chart_renderer');
    $build = $r->render('bar', ['Mon' => 3, 'Tue' => 5], [
      'title' => 'Volume',
      'drill_url' => '/admin/reports/audit-chain',
    ]);
    $this->assertArrayNotHasKey('#type', $build);
    $rendered = (string) \Drupal::service('renderer')->renderRoot($build);
    $this->assertStringContainsString('<svg', $rendered);
    $this->assertStringContainsString('Volume', $rendered);
    $this->assertStringContainsString('/admin/reports/audit-chain', $rendered);
    $this->assertStringContainsString('audit-chain-chart__svg', $rendered);
  }

  /**
   * @covers ::render
   */
  public function testLineFallbackReturnsInlineSvg(): void {
    /** @var \Drupal\audit_chain\AuditChainChartRenderer $r */
    $r = \Drupal::service('audit_chain.chart_renderer');
    $build = $r->render('line', ['00:00' => 1, '01:00' => 4, '02:00' => 2], ['title' => 'Trend']);
    $rendered = (string) \Drupal::service('renderer')->renderRoot($build);
    $this->assertStringContainsString('<svg', $rendered);
    $this->assertStringContainsString('Trend', $rendered);
    $this->assertStringContainsString('audit-chain-chart__line', $rendered);
  }

  /**
   * @covers ::render
   */
  public function testDonutFallbackReturnsInlineSvg(): void {
    /** @var \Drupal\audit_chain\AuditChainChartRenderer $r */
    $r = \Drupal::service('audit_chain.chart_renderer');
    $build = $r->render('donut', ['personnel' => 8, 'mcp' => 2], ['title' => 'Split']);
    $rendered = (string) \Drupal::service('renderer')->renderRoot($build);
    $this->assertStringContainsString('<svg', $rendered);
    $this->assertStringContainsString('audit-chain-chart__slice', $rendered);
  }

  /**
   * @covers ::render
   */
  public function testEmptySeriesRendersEmptyState(): void {
    /** @var \Drupal\audit_chain\AuditChainChartRenderer $r */
    $r = \Drupal::service('audit_chain.chart_renderer');
    $build = $r->render('bar', [], ['title' => 'X']);
    $this->assertArrayNotHasKey('#type', $build);
    $rendered = (string) \Drupal::service('renderer')->renderRoot($build);
    $this->assertStringContainsString('No data', $rendered);
    $this->assertStringNotContainsString('<svg', $rendered);
  }

  /**
   * Charts enabled with no library plugin must still emit inline SVG.
   *
   * @covers ::render
   */
  public function testSvgFallbackWhenChartsHasNoLibraryPlugin(): void {
    $moduleHandler = $this->createMock(ModuleHandlerInterface::class);
    $moduleHandler->method('moduleExists')->with('charts')->willReturn(TRUE);
    $manager = $this->createMock(PluginManagerInterface::class);
    $manager->method('getDefinitions')->willReturn([]);
    $renderer = new AuditChainChartRenderer($moduleHandler, $manager);
    $build = $renderer->render('bar', ['Mon' => 3, 'Tue' => 5], ['title' => 'Volume']);
    $this->assertArrayNotHasKey('#type', $build);
    $this->assertStringContainsString('audit-chain-chart--bar', (string) $build['#prefix']);
    $this->assertArrayHasKey('svg', $build);
  }

  /**
   * Charts plus a library plugin still upgrades to `#type => chart`.
   *
   * @covers ::render
   */
  public function testChartsElementWhenLibraryPluginExists(): void {
    $moduleHandler = $this->createMock(ModuleHandlerInterface::class);
    $moduleHandler->method('moduleExists')->with('charts')->willReturn(TRUE);
    $manager = $this->createMock(PluginManagerInterface::class);
    $manager->method('getDefinitions')->willReturn(['chartjs' => []]);
    $renderer = new AuditChainChartRenderer($moduleHandler, $manager);
    $build = $renderer->render('bar', ['Mon' => 3], ['title' => 'Volume']);
    $this->assertSame('chart', $build['#type']);
  }

  /**
   * @covers ::render
   */
  public function testChartsElementWhenLibraryPresent(): void {
    if (!\Drupal::moduleHandler()->moduleExists('charts')) {
      $this->markTestSkipped('drupal/charts not installed.');
    }
    $definitions = \Drupal::hasService('plugin.manager.charts')
      ? \Drupal::service('plugin.manager.charts')->getDefinitions()
      : [];
    if ($definitions === []) {
      $this->markTestSkipped('Charts is installed without a library plugin.');
    }
    /** @var \Drupal\audit_chain\AuditChainChartRenderer $r */
    $r = \Drupal::service('audit_chain.chart_renderer');
    $build = $r->render('bar', ['Mon' => 3], ['title' => 'Volume']);
    $chart = $build['#type'] ?? ($build['content']['#type'] ?? NULL);
    $this->assertSame('chart', $chart);
  }

}
