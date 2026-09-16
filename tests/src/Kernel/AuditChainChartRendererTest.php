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
  public function testDonutFallbackReturnsInlineSvg(): void {
    /** @var \Drupal\audit_chain\AuditChainChartRenderer $r */
    $r = \Drupal::service('audit_chain.chart_renderer');
    $build = $r->render('donut', ['personnel' => 8, 'mcp' => 2], ['title' => 'Split']);
    $this->assertArrayNotHasKey('#type', $build);
    $rendered = (string) \Drupal::service('renderer')->renderRoot($build);
    $this->assertStringContainsString('<svg', $rendered);
    $this->assertStringContainsString('Split', $rendered);
    $this->assertStringContainsString('audit-chain-chart__svg', $rendered);
    $this->assertStringContainsString('audit-chain-chart__slice', $rendered);
  }

  /**
   * @covers ::render
   */
  public function testEmptySeriesRendersEmptyState(): void {
    /** @var \Drupal\audit_chain\AuditChainChartRenderer $r */
    $r = \Drupal::service('audit_chain.chart_renderer');
    $build = $r->render('donut', [], ['title' => 'X']);
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
    $build = $renderer->render('donut', ['Keyed' => 3, 'Unkeyed' => 5], ['title' => 'Keyed vs unkeyed']);
    $this->assertArrayNotHasKey('#type', $build);
    $this->assertStringContainsString('audit-chain-chart--donut', (string) $build['#prefix']);
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
    $build = $renderer->render('donut', ['Keyed' => 3], ['title' => 'Keyed vs unkeyed']);
    $this->assertSame('chart', $build['#type']);
    $this->assertSame('pie', $build['#chart_type']);
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
    $build = $r->render('donut', ['Keyed' => 3], ['title' => 'Keyed vs unkeyed']);
    $this->assertSame('chart', $build['#type'] ?? NULL);
  }

}
