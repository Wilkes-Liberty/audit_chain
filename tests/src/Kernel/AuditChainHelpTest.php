<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain\Kernel;

use Drupal\Core\Routing\NullRouteMatch;
use Drupal\Core\Routing\RouteMatchInterface;
use Drupal\Core\Url;
use Drupal\KernelTests\KernelTestBase;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel tests for hook_help two-arg invoke and routed hrefs.
 *
 * @group audit_chain
 *
 * @runTestsInSeparateProcesses
 */
#[Group('audit_chain')]
#[RunTestsInSeparateProcesses]
final class AuditChainHelpTest extends KernelTestBase {

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
    $this->installConfig(['system', 'audit_chain']);
    $this->container->get('router.builder')->rebuild();
  }

  /**
   * Invokes hook_help() with two arguments and asserts routed hrefs.
   */
  public function testHelpAcceptsTwoArgInvokeAndUsesRoutedHrefs(): void {
    $parameters = (new \ReflectionFunction('audit_chain_help'))->getParameters();
    $this->assertCount(2, $parameters);
    $this->assertSame('route_match', $parameters[1]->getName());
    $this->assertInstanceOf(\ReflectionNamedType::class, $parameters[1]->getType());
    $this->assertSame(RouteMatchInterface::class, $parameters[1]->getType()->getName());

    $output = \Drupal::moduleHandler()->invoke('audit_chain', 'help', [
      'help.page.audit_chain',
      new NullRouteMatch(),
    ]);

    $this->assertIsString($output);
    $this->assertStringContainsString(Url::fromRoute('audit_chain.settings')->toString(), $output);
    $this->assertStringContainsString(Url::fromRoute('audit_chain.dashboard')->toString(), $output);
    $this->assertStringContainsString('Configuration → System → Audit Chain', $output);
    $this->assertStringContainsString('Reports → Audit Chain', $output);
  }

  /**
   * Dashboard help still returns for the reports route via two-arg invoke.
   */
  public function testDashboardHelpViaTwoArgInvoke(): void {
    $output = \Drupal::moduleHandler()->invoke('audit_chain', 'help', [
      'audit_chain.dashboard',
      new NullRouteMatch(),
    ]);

    $this->assertIsString($output);
    $this->assertStringContainsString('Integrity and the keyed-vs-unkeyed split', $output);
  }

}
