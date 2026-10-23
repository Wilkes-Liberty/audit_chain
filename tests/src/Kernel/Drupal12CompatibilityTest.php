<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain\Kernel;

use Drupal\Component\Serialization\Yaml;
use Drupal\KernelTests\KernelTestBase;
use PHPUnit\Framework\Attributes\Group;

/**
 * Pins the Drupal 12 compatibility claim so a revert fails CI.
 *
 * @group audit_chain
 */
#[Group('audit_chain')]
final class Drupal12CompatibilityTest extends KernelTestBase {

  use RuntimeRequirementsTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system',
    'user',
    'key',
    'encrypt',
    'audit_chain',
  ];

  /**
   * The base module and composer.json advertise Drupal 12.
   */
  public function testBaseModuleDeclaresDrupal12(): void {
    $root = dirname(__DIR__, 3);
    $info = Yaml::decode((string) file_get_contents($root . '/audit_chain.info.yml'));
    $this->assertIsArray($info);
    $this->assertArrayHasKey('core_version_requirement', $info);
    $this->assertSame('^10.6 || ^11.3 || ^12', $info['core_version_requirement']);

    $composer = json_decode((string) file_get_contents($root . '/composer.json'), TRUE);
    $this->assertIsArray($composer);
    $this->assertSame('^10.6 || ^11.3 || ^12', $composer['require']['drupal/core']);
  }

  /**
   * The MCP submodule stays inside MCP Sentinel's declared range.
   */
  public function testMcpSubmoduleDoesNotClaimDrupal12(): void {
    $root = dirname(__DIR__, 3);
    $info = Yaml::decode((string) file_get_contents($root . '/modules/audit_chain_mcp/audit_chain_mcp.info.yml'));
    $this->assertIsArray($info);
    $this->assertSame('^10.6 || ^11.3', $info['core_version_requirement']);
    $this->assertStringNotContainsString('^12', $info['core_version_requirement']);
  }

  /**
   * The installed core discovers the runtime requirements hook.
   */
  public function testRuntimeRequirementsHookIsDiscoverable(): void {
    $requirements = $this->runtimeRequirements();
    $this->assertIsArray($requirements);
  }

  /**
   * Severity uses the enum on 11.2+ and the matching integer on 10.6.
   */
  public function testSeverityMatchesThisCore(): void {
    $actual = $this->requirementSeverity('crit');
    // 11.2+ / 12 return the backed enum; 10.6 still uses the integer 2.
    if (is_object($actual)) {
      $this->assertTrue(property_exists($actual, 'value'));
      $this->assertSame(2, $actual->value);
      return;
    }
    $this->assertSame(2, $actual);
  }

}
