<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain\Kernel;

use Drupal\audit_chain\Controller\AuditChainDashboardController;
use Drupal\audit_chain\ScheduledVerifier;
use Drupal\Core\Session\AnonymousUserSession;
use Drupal\Core\Url;
use Drupal\KernelTests\KernelTestBase;
use Drupal\Tests\user\Traits\UserCreationTrait;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;

/**
 * Kernel tests for the reports dashboard controller.
 *
 * @coversDefaultClass \Drupal\audit_chain\Controller\AuditChainDashboardController
 *
 * @group audit_chain
 *
 * @runTestsInSeparateProcesses
 */
#[CoversClass(AuditChainDashboardController::class)]
#[Group('audit_chain')]
#[RunTestsInSeparateProcesses]
final class AuditChainDashboardTest extends KernelTestBase {

  use AuditChainSchemaTrait;
  use UserCreationTrait;

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
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installAuditChainTables();
    $this->installEntitySchema('user');
    $this->installSchema('user', ['users_data']);
    $this->installConfig(['system', 'user', 'audit_chain']);
    $this->container->get('router.builder')->rebuild();
  }

  /**
   * Inserts a chain row with only the indexed columns the dashboard reads.
   */
  private function insertRow(string $channel, string $operation, string $keyId = ''): void {
    $this->container->get('database')->insert('audit_chain_log')->fields([
      'channel' => $channel,
      'timestamp' => \Drupal::time()->getRequestTime() - 60,
      'uid' => 1,
      'operation' => $operation,
      'key_id' => $keyId,
    ])->execute();
  }

  /**
   * The dashboard renders the integrity card and keyed-vs-unkeyed chart.
   *
   * @covers ::dashboard
   */
  public function testDashboardRendersIntegrityAndKeyedSplit(): void {
    $this->insertRow('personnel', 'field_read', 'hmac');
    $this->insertRow('mcp', 'tool_call', '');

    $request = Request::create('/admin/reports/audit-chain', 'GET', ['window' => '24h']);
    $controller = AuditChainDashboardController::create($this->container);
    $build = $controller->dashboard($request);
    $rendered = (string) $this->container->get('renderer')->renderRoot($build);

    $this->assertSame('audit_chain_dashboard', $build['#theme']);
    $this->assertCount(1, $build['#charts']);
    $this->assertStringContainsString('audit-chain-dashboard', $rendered);
    $this->assertSame(1, substr_count($rendered, 'audit-chain-chart-cell'));
    $this->assertStringContainsString('Hash chain', $rendered);
    $this->assertStringContainsString('Keyed vs unkeyed', $rendered);
    $this->assertStringNotContainsString('Volume', $rendered);
    $this->assertStringNotContainsString('By channel', $rendered);
    $this->assertStringNotContainsString('By operation', $rendered);
    $this->assertStringNotContainsString('No charting library found', $rendered);
    $this->assertStringNotContainsString('field_salary', $rendered);
    $this->assertStringContainsString('window=7d', $rendered);
    $this->assertStringContainsString('window=30d', $rendered);
  }

  /**
   * The post-activate successor card is pending, not a verification failure.
   *
   * @covers ::dashboard
   */
  public function testAwaitingVerificationDoesNotPrintVerificationFailed(): void {
    $this->container->get('state')->set(ScheduledVerifier::STATE_KEY, [
      'time' => \Drupal::time()->getRequestTime(),
      'ok' => FALSE,
      'reason' => 'tampered',
      'successor' => [
        'segment_ok' => FALSE,
        'historical_ok' => FALSE,
        'reason' => 'awaiting_verification',
        'segment_id' => '957345ba-a0c8-42d5-9dcb-92ba4430a820',
      ],
    ]);

    $request = Request::create('/admin/reports/audit-chain');
    $controller = AuditChainDashboardController::create($this->container);
    $build = $controller->dashboard($request);
    $rendered = (string) $this->container->get('renderer')->renderRoot($build);

    $this->assertStringContainsString('Successor segment', $rendered);
    $this->assertStringContainsString('Awaiting verification', $rendered);
    $this->assertStringNotContainsString('Verification failed', $rendered);
    $this->assertStringContainsString('audit-chain-card--warn', $rendered);
  }

  /**
   * A disclosed historical fork with a healthy successor is a warning.
   *
   * @covers ::dashboard
   */
  public function testDocumentedHistoricalExceptionIsWarningNotFailed(): void {
    $this->config('audit_chain.settings')->set('verify_interval', 3600)->save();
    $this->container->get('state')->set(ScheduledVerifier::STATE_KEY, [
      'time' => \Drupal::time()->getRequestTime(),
      'ok' => FALSE,
      'reason' => 'tampered',
      'verdict' => [
        'ok' => FALSE,
        'reason' => 'tampered',
        'broken_at' => 11425,
      ],
      'successor' => [
        'segment_ok' => TRUE,
        'historical_ok' => FALSE,
        'reason' => NULL,
        'segment_id' => '957345ba-a0c8-42d5-9dcb-92ba4430a820',
        'historical_verdict' => [
          'ok' => FALSE,
          'reason' => 'tampered',
          'broken_at' => 11425,
        ],
      ],
    ]);

    $request = Request::create('/admin/reports/audit-chain');
    $controller = AuditChainDashboardController::create($this->container);
    $build = $controller->dashboard($request);
    $rendered = (string) $this->container->get('renderer')->renderRoot($build);

    $this->assertSame('warn', $build['#chain']['state']);
    $this->assertSame('Historical exception', $build['#chain']['label']);
    $this->assertStringContainsString('11425', $build['#chain']['detail']);
    $this->assertStringContainsString('957345ba-a0c8-42d5-9dcb-92ba4430a820', $build['#chain']['detail']);
    $this->assertStringContainsString('historical_ok=false', $build['#chain']['detail']);
    $this->assertStringContainsString('segment_ok=true', $build['#chain']['detail']);
    $this->assertStringContainsString('documented preserved failure', $build['#chain']['detail']);
    $this->assertStringContainsString('audit-chain:verify', $build['#chain']['detail']);
    $this->assertStringContainsString('Historical exception', $rendered);
    $this->assertStringContainsString('audit-chain-card--warn', $rendered);
    $this->assertStringNotContainsString('Hash chain: Failed', $rendered);
  }

  /**
   * An unknown window query argument is ignored.
   *
   * @covers ::dashboard
   */
  public function testUnknownWindowQueryFallsBackToDefault(): void {
    $request = Request::create('/admin/reports/audit-chain', 'GET', ['window' => 'forever']);
    $controller = AuditChainDashboardController::create($this->container);
    $build = $controller->dashboard($request);
    $this->assertSame('24h', $build['#window']);
  }

  /**
   * Empty series render the empty-state, not a Charts error.
   *
   * @covers ::dashboard
   */
  public function testEmptyDashboardShowsNoDataNotChartsError(): void {
    $request = Request::create('/admin/reports/audit-chain');
    $controller = AuditChainDashboardController::create($this->container);
    $build = $controller->dashboard($request);
    $rendered = (string) $this->container->get('renderer')->renderRoot($build);
    $this->assertStringContainsString('No data', $rendered);
    $this->assertStringNotContainsString('No charting library found', $rendered);
  }

  /**
   * The reports permission is restrict-access and not granted by default.
   *
   * @coversNothing
   */
  public function testReportsPermissionIsNotGrantedByDefault(): void {
    $this->assertFalse((new AnonymousUserSession())->hasPermission('view audit chain reports'));
    $account = $this->createUser(['view audit chain reports']);
    $this->assertTrue($account->hasPermission('view audit chain reports'));
    $definitions = $this->container->get('user.permissions')->getPermissions();
    $this->assertArrayHasKey('view audit chain reports', $definitions);
    $this->assertTrue(!empty($definitions['view audit chain reports']['restrict access']));
  }

  /**
   * Reports-only users do not receive a Settings href.
   *
   * @covers ::dashboard
   */
  public function testReportsOnlyUserDoesNotGetSettingsHref(): void {
    // setUpCurrentUser() creates uid 1 first so this account is not the
    // superuser, which would bypass the settings-route access check.
    $account = $this->setUpCurrentUser([], ['view audit chain reports']);
    $this->assertGreaterThan(1, (int) $account->id());
    $this->assertFalse($account->hasPermission('administer site configuration'));

    $request = Request::create('/admin/reports/audit-chain');
    $controller = AuditChainDashboardController::create($this->container);
    $build = $controller->dashboard($request);
    $rendered = (string) $this->container->get('renderer')->renderRoot($build);

    $settingsUrl = Url::fromRoute('audit_chain.settings')->toString();
    $this->assertSame([], $build['#quick_actions']);
    $this->assertStringNotContainsString('Settings', $rendered);
    $this->assertStringNotContainsString($settingsUrl, $rendered);
  }

  /**
   * Settings-capable users receive the Settings href.
   *
   * @covers ::dashboard
   */
  public function testSettingsCapableUserGetsSettingsHref(): void {
    $account = $this->setUpCurrentUser([], [
      'view audit chain reports',
      'administer site configuration',
    ]);
    $this->assertGreaterThan(1, (int) $account->id());
    $this->assertTrue($account->hasPermission('administer site configuration'));

    $request = Request::create('/admin/reports/audit-chain');
    $controller = AuditChainDashboardController::create($this->container);
    $build = $controller->dashboard($request);
    $rendered = (string) $this->container->get('renderer')->renderRoot($build);
    $settingsUrl = Url::fromRoute('audit_chain.settings')->toString();

    $this->assertCount(1, $build['#quick_actions']);
    $this->assertSame('Settings', $build['#quick_actions'][0]['title']);
    $this->assertSame($settingsUrl, $build['#quick_actions'][0]['url']);
    $this->assertStringContainsString('Settings', $rendered);
    $this->assertStringContainsString($settingsUrl, $rendered);
  }

}
