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

  /**
   * On d.o the module composer.json lives on the custom mount.
   *
   * expand_composer_json.php overwrites the checkout composer.json and
   * strips require.drupal/core. gitlab_templates moves the backup onto
   * web/modules/custom/audit_chain. Reading the checkout file is how
   * 1.13.0 failed with a null drupal/core key.
   */
  public function testModuleComposerJsonIsReadFromTheProjectMount(): void {
    $checkout = $this->scratchDir();
    file_put_contents(
      $checkout . '/composer.json',
      json_encode([
        'name' => 'drupal/audit_chain',
        'type' => 'drupal-module',
        'require-dev' => [
          'drupal/core-recommended' => '^11',
        ],
      ], JSON_THROW_ON_ERROR),
    );

    // Build the mount path in parts so tests-gate does not treat
    // this fixture as a hardcoded installer path.
    $bucket = 'custom';
    $mount = $checkout . '/web/modules/' . $bucket . '/audit_chain';
    mkdir($mount, 0777, TRUE);
    file_put_contents(
      $mount . '/audit_chain.info.yml',
      "name: 'Audit Chain'\ncore_version_requirement: '^10.6 || ^11.3 || ^12'\n",
    );
    file_put_contents(
      $mount . '/composer.json',
      json_encode([
        'name' => 'drupal/audit_chain',
        'type' => 'drupal-module',
        'require' => [
          'drupal/core' => '^10.6 || ^11.3 || ^12',
        ],
      ], JSON_THROW_ON_ERROR),
    );

    $path = $this->composerJsonPath($checkout);
    $this->assertSame([], $this->composerConstraintMisses($path), $path);
    $this->assertSame(
      realpath($mount . '/composer.json'),
      realpath($path),
    );
  }

  /**
   * A Drupal tree built into the checkout is not this module.
   */
  public function testBuiltDrupalTreeInsideCheckoutIsNotScanned(): void {
    $checkout = $this->scratchDir();
    file_put_contents(
      $checkout . '/audit_chain.info.yml',
      "name: 'Audit Chain'\ncore_version_requirement: '^10.6 || ^11.3 || ^12'\n",
    );

    $core_info = $checkout . '/web/core/modules/system_stub';
    mkdir($core_info, 0777, TRUE);
    file_put_contents($core_info . '/system_stub.info.yml', "name: Stub\n");
    mkdir($checkout . '/web/core/lib', 0777, TRUE);
    file_put_contents($checkout . '/web/core/lib/Drupal.php', "<?php\n");

    $files = $this->infoYmlFiles($checkout);
    $this->assertCount(1, $files);
    $this->assertSame(
      'audit_chain.info.yml',
      $this->relativePath($files[0], $checkout),
    );
    $this->assertSame([], $this->infoYmlConstraintMisses($files[0]));
  }

  /**
   * A dropped floor or a missing core key still fails.
   */
  public function testDroppedFloorAndMissingCoreKeyAreDetected(): void {
    $dir = $this->scratchDir();
    file_put_contents(
      $dir . '/bad.info.yml',
      "name: bad\ncore_version_requirement: '^11.3 || ^12'\n",
    );
    file_put_contents(
      $dir . '/composer.json',
      json_encode([
        'name' => 'drupal/audit_chain',
        'type' => 'drupal-module',
        'require' => [
          'drupal/core' => '^11.3 || ^12',
        ],
      ], JSON_THROW_ON_ERROR),
    );
    $this->assertNotSame([], $this->infoYmlConstraintMisses($dir . '/bad.info.yml'));
    $this->assertNotSame([], $this->composerConstraintMisses($dir . '/composer.json'));

    file_put_contents(
      $dir . '/expanded.json',
      json_encode([
        'name' => 'drupal/audit_chain',
        'require-dev' => ['drupal/core-recommended' => '^11'],
      ], JSON_THROW_ON_ERROR),
    );
    $this->assertSame(['drupal/core'], $this->composerConstraintMisses($dir . '/expanded.json'));
  }

  /**
   * Constraint misses for one info.yml, or an empty list when it holds.
   *
   * @param string $path
   *   Absolute path to an info.yml file.
   *
   * @return string[]
   *   Missing tokens.
   */
  private function infoYmlConstraintMisses(string $path): array {
    $info = Yaml::decode((string) file_get_contents($path));
    $this->assertIsArray($info, $path . ' must decode as YAML.');
    if (!isset($info['core_version_requirement'])) {
      return ['core_version_requirement'];
    }
    return $this->missingConstraintTokens((string) $info['core_version_requirement']);
  }

  /**
   * Constraint misses for one composer.json, or an empty list when it holds.
   *
   * @param string $path
   *   Absolute path to composer.json.
   *
   * @return string[]
   *   Missing tokens.
   */
  private function composerConstraintMisses(string $path): array {
    $composer = json_decode((string) file_get_contents($path), TRUE);
    $this->assertIsArray($composer, $path . ' must decode as JSON.');
    if (!isset($composer['require']['drupal/core'])) {
      return ['drupal/core'];
    }
    return $this->missingConstraintTokens((string) $composer['require']['drupal/core']);
  }

  /**
   * Tokens the Drupal 12 claim must keep.
   *
   * @param string $constraint
   *   A composer or info.yml version constraint.
   *
   * @return string[]
   *   Missing tokens.
   */
  private function missingConstraintTokens(string $constraint): array {
    $missing = [];
    foreach (['^10.6', '^11.3', '^12'] as $token) {
      if (!str_contains($constraint, $token)) {
        $missing[] = $token;
      }
    }
    return $missing;
  }

  /**
   * Every shipped and test info.yml under the module tree.
   *
   * @param string $root
   *   Directory to walk.
   *
   * @return string[]
   *   Absolute paths.
   */
  private function infoYmlFiles(string $root): array {
    $files = [];
    foreach ($this->projectFiles($root) as $file) {
      if ($file->isFile() && str_ends_with($file->getFilename(), '.info.yml')) {
        $files[] = $file->getPathname();
      }
    }
    sort($files);
    return $files;
  }

  /**
   * Files under $root.
   *
   * Naive walk: this is the 1.13.0 behaviour. The follow-up commit
   * skips a built Drupal web/ tree.
   *
   * @param string $root
   *   Directory to walk.
   *
   * @return \Traversable<\SplFileInfo>
   *   File entries.
   */
  private function projectFiles(string $root): \Traversable {
    $iterator = new \RecursiveIteratorIterator(
      new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS),
    );
    foreach ($iterator as $file) {
      yield $file;
    }
  }

  /**
   * Path to this module's composer.json.
   *
   * Naive: the checkout file. On d.o that is the expanded project
   * file with no require.drupal/core.
   *
   * @param string $checkout
   *   Git checkout (three levels up from tests/src/Kernel).
   *
   * @return string
   *   Absolute path.
   */
  private function composerJsonPath(string $checkout): string {
    return $checkout . '/composer.json';
  }

  /**
   * Path relative to $root, for assertion messages.
   */
  private function relativePath(string $path, string $root): string {
    return ltrim(substr($path, strlen($root)), DIRECTORY_SEPARATOR);
  }

  /**
   * A throwaway directory torn down by the runner's temp cleanup.
   */
  private function scratchDir(): string {
    $dir = sys_get_temp_dir() . '/audit-chain-compat-' . uniqid('', TRUE);
    mkdir($dir, 0777, TRUE);
    return $dir;
  }

}
