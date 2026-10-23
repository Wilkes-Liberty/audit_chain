<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain\Kernel;

use Drupal\audit_chain\Hook\AuditChainRequirements;

/**
 * Exercises the runtime hook the installed core uses for its status report.
 */
trait RuntimeRequirementsTrait {

  /**
   * Reads requirements through the module handler, asserting hook discovery.
   *
   * Drupal 10.6 still calls hook_requirements($phase). 11.2+ calls
   * hook_runtime_requirements() and skips the legacy bridge.
   *
   * @return array<string, array<string, mixed>>
   *   Runtime findings keyed by requirement ID.
   */
  private function runtimeRequirements(): array {
    $module_handler = $this->container->get('module_handler');
    $legacy = version_compare(\Drupal::VERSION, '11.2', '<');
    if ($legacy) {
      $module_handler->loadInclude('audit_chain', 'install');
    }
    $hook = $legacy ? 'requirements' : 'runtime_requirements';
    $this->assertTrue($module_handler->hasImplementations($hook, 'audit_chain'));
    $requirements = $module_handler->invoke('audit_chain', $hook, $legacy ? ['runtime'] : []);
    $this->assertIsArray($requirements);
    return $requirements;
  }

  /**
   * Severity value the status report uses on this core version.
   *
   * @param string $level
   *   One of ok, crit, warn.
   *
   * @return mixed
   *   RequirementSeverity on 11.2+ / 12, or the matching integer on 10.6.
   */
  private function requirementSeverity(string $level): mixed {
    return AuditChainRequirements::severity($level);
  }

}
