<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain\Kernel;

use Drupal\audit_chain\Controller\AuditChainDashboardController;
use Drupal\Core\Session\AnonymousUserSession;
use Drupal\KernelTests\KernelTestBase;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use Drupal\user\RoleInterface;
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
    $this->installSchema('audit_chain', ['audit_chain_log']);
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
   * The dashboard renders four chart cells and the integrity card.
   *
   * @covers ::dashboard
   */
  public function testDashboardRendersChartsAndIntegrityCard(): void {
    $this->insertRow('personnel', 'field_read', 'hmac');
    $this->insertRow('mcp', 'tool_call', '');

    $request = Request::create('/admin/reports/audit-chain', 'GET', ['window' => '24h']);
    $controller = AuditChainDashboardController::create($this->container);
    $build = $controller->dashboard($request);
    $rendered = (string) $this->container->get('renderer')->renderRoot($build);

    $this->assertSame('audit_chain_dashboard', $build['#theme']);
    $this->assertCount(4, $build['#charts']);
    $this->assertStringContainsString('audit-chain-dashboard', $rendered);
    $this->assertStringContainsString('audit-chain-chart-cell', $rendered);
    $this->assertSame(4, substr_count($rendered, 'audit-chain-chart-cell'));
    $this->assertStringContainsString('Hash chain', $rendered);
    $this->assertStringContainsString('Volume', $rendered);
    $this->assertStringContainsString('By channel', $rendered);
    $this->assertStringContainsString('By operation', $rendered);
    $this->assertStringContainsString('Keyed vs unkeyed', $rendered);
    $this->assertStringNotContainsString('No charting library found', $rendered);
    $this->assertStringNotContainsString('field_salary', $rendered);
    $this->assertStringContainsString('window=7d', $rendered);
    $this->assertStringContainsString('window=30d', $rendered);
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
   * The reports route is forbidden without the restrict-access permission.
   *
   * @coversNothing
   */
  public function testDashboardRouteRequiresPermission(): void {
    $access = $this->container->get('access_manager');
    $denied = $access->checkNamedRoute('audit_chain.dashboard', [], new AnonymousUserSession(), TRUE);
    $this->assertTrue($denied->isForbidden());

    $role = Role::load(RoleInterface::AUTHENTICATED_ID);
    $this->assertNotNull($role);
    $role->grantPermission('view audit chain reports');
    $role->save();

    $account = $this->createUser([]);
    $allowed = $access->checkNamedRoute('audit_chain.dashboard', [], $account, TRUE);
    $this->assertTrue($allowed->isAllowed());
  }

}
