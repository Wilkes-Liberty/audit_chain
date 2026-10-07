<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain\Kernel;

use Drupal\audit_chain\Controller\AuditChainDashboardController;
use Drupal\audit_chain\Event\AuditChainVerificationFailedEvent;
use Drupal\audit_chain\RewindDetector;
use Drupal\audit_chain\Witness\WitnessDnsResolverInterface;
use Drupal\audit_chain\Witness\WitnessTransportInterface;
use Drupal\Core\Site\Settings;
use Drupal\KernelTests\KernelTestBase;
use Drupal\key\Entity\Key;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;

/**
 * A database restore that leaves a consistent chain (d.o #3627532).
 *
 * The high-water mark is the latest confirmed XRPL witness. Receipts and
 * checkpoints live in the same database, so the test deletes them with the
 * rewound rows and leaves the ledger response in place.
 *
 * @group audit_chain
 *
 * @runTestsInSeparateProcesses
 */
#[Group('audit_chain')]
#[RunTestsInSeparateProcesses]
final class ChainRewindTest extends KernelTestBase {

  use AuditChainSchemaTrait;

  private const WITNESS_ACCOUNT = 'rWitness11111111111111111111111';

  private const SINK = 'rSink11111111111111111111111111';

  /**
   * Scripted HTTP double.
   */
  private RewindScriptTransport $transport;

  /**
   * Failure events captured during the test.
   *
   * @var list<array>
   */
  private array $captured = [];

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
    $this->transport = new RewindScriptTransport();
    $this->container->set('audit_chain.witness_transport', $this->transport);
    $this->container->set('audit_chain.witness_dns', new RewindMapDns([
      'read.example' => ['1.1.1.1'],
      'relay.example' => ['1.1.1.1'],
    ]));
    $this->installEntitySchema('user');
    $this->installSchema('user', ['users_data']);
    $this->installAuditChainTables();
    $this->installConfig(['system', 'user', 'audit_chain']);
    $this->container->get('router.builder')->rebuild();
    new Settings([
      'audit_chain_instance_id' => 'rewind-test-instance',
      'audit_chain_witness_xrpl_token' => 'relay-test-token',
    ] + Settings::getAll());
    Key::create([
      'id' => 'rewind_key',
      'label' => 'Rewind test key',
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => 'rewind-test-secret'],
    ])->save();
    $this->config('audit_chain.settings')
      ->set('hash_key', 'rewind_key')
      ->set('verify_interval', 3600)
      ->save();
    $this->container->get('event_dispatcher')->addListener(
      AuditChainVerificationFailedEvent::EVENT_NAME,
      function (AuditChainVerificationFailedEvent $event): void {
        $this->captured[] = $event->run;
      }
    );
  }

  /**
   * A restored chain that still verifies fails against the external witness.
   */
  public function testRestoreFailsAgainstExternalWitness(): void {
    $this->configureXrpl();
    $logger = $this->container->get('audit_chain.logger');
    $logger->logKeyed('personnel', 'before_restore');
    $logger->logKeyed('personnel', 'witnessed');
    $logger->logKeyed('personnel', 'later');
    $bundle = $this->container->get('audit_chain.archive_bundle_exporter')->create();
    $digest = $bundle['manifest']['digest'];
    $through = $bundle['manifest']['window']['through_id'];
    $this->scriptTransactions([$this->witnessPayment($digest, 42)]);

    $matched = $this->container->get('audit_chain.scheduled_verifier')->runNow();
    $this->assertTrue($matched['ok']);
    $this->assertNull($matched['reason']);
    $this->assertTrue($matched['verdict']['ok']);
    $this->assertSame(RewindDetector::STATUS_MATCHES, $matched['rewind']['status']);
    $this->assertSame($digest, $matched['rewind']['digest']);
    $this->assertSame($through, $matched['rewind']['through_id']);
    $this->assertSame([], $this->captured);
    $this->assertSame(
      'https://read.example/accounts/' . self::WITNESS_ACCOUNT . '/transactions',
      $this->transport->calls[0]['url'],
    );
    $this->assertSame('GET', $this->transport->calls[0]['method']);
    $this->assertArrayNotHasKey('Authorization', $this->transport->calls[0]['headers']);

    $database = $this->container->get('database');
    $database->delete('audit_chain_log')->condition('id', 1, '>')->execute();
    $database->truncate('audit_chain_checkpoint')->execute();
    $database->truncate('audit_chain_witness_receipt')->execute();
    $logger->logKeyed('personnel', 'after_restore');
    $verdict = $logger->verify();
    $this->assertTrue($verdict['ok']);
    $this->assertNull($verdict['reason']);
    $this->scriptTransactions([$this->witnessPayment($digest, 42)]);
    $before = $this->chainSnapshot();

    $run = $this->container->get('audit_chain.scheduled_verifier')->runNow();
    $this->assertFalse($run['ok']);
    $this->assertSame(RewindDetector::REASON_REWOUND, $run['reason']);
    $this->assertTrue($run['verdict']['ok']);
    $this->assertSame(RewindDetector::STATUS_REWOUND, $run['rewind']['status']);
    $this->assertSame($digest, $run['rewind']['digest']);
    $this->assertNull($run['rewind']['through_id']);
    $this->assertCount(1, $this->captured);
    $this->assertSame(RewindDetector::REASON_REWOUND, $this->captured[0]['reason']);
    $this->assertSame($before, $this->chainSnapshot());

    $requirements = $this->runtimeRequirements();
    $requirement = $requirements['audit_chain_scheduled_verification'];
    $this->assertSame(REQUIREMENT_ERROR, $requirement['severity']);
    $this->assertStringContainsString('CHAIN REWOUND', (string) $requirement['value']);

    $controller = AuditChainDashboardController::create($this->container);
    $build = $controller->dashboard(Request::create('/admin/reports/audit-chain'));
    $rendered = (string) $this->container->get('renderer')->renderRoot($build);
    $this->assertSame('crit', $build['#chain']['state']);
    $this->assertSame('Chain rewound', $build['#chain']['label']);
    $this->assertStringContainsString('Chain rewound', $rendered);
    $this->assertStringContainsString('not in this database', $build['#chain']['detail']);
  }

  /**
   * A witness read failure leaves the hash-chain result and does not alert.
   */
  public function testUnreachableWitnessDoesNotFailTheChain(): void {
    $this->configureXrpl();
    $this->container->get('audit_chain.logger')->logKeyed('personnel', 'still_here');
    $this->transport->script[] = ['status' => 500, 'body' => ''];

    $run = $this->container->get('audit_chain.scheduled_verifier')->runNow();
    $this->assertCount(1, $this->transport->calls);
    $this->assertTrue($run['ok']);
    $this->assertNull($run['reason']);
    $this->assertSame(RewindDetector::STATUS_UNCHECKED, $run['rewind']['status']);
    $this->assertSame(RewindDetector::REASON_UNREACHABLE, $run['rewind']['reason']);
    $this->assertSame([], $this->captured);

    $requirements = $this->runtimeRequirements();
    $requirement = $requirements['audit_chain_scheduled_verification'];
    $this->assertSame(REQUIREMENT_WARNING, $requirement['severity']);
    $this->assertStringContainsString('Rewind check unavailable', (string) $requirement['value']);
  }

  /**
   * An empty witness list is the absence of a mark, not a rewind.
   */
  public function testEmptyWitnessListDoesNotFail(): void {
    $this->configureXrpl();
    $this->container->get('audit_chain.logger')->logKeyed('personnel', 'unwitnessed');
    $this->scriptTransactions([]);

    $run = $this->container->get('audit_chain.scheduled_verifier')->runNow();
    $this->assertTrue($run['ok']);
    $this->assertSame(RewindDetector::STATUS_ABSENT, $run['rewind']['status']);
    $this->assertSame([], $this->captured);
  }

  /**
   * Two checkpoint digests at the newest ledger index stay unchecked.
   */
  public function testAmbiguousWitnessStaysUnchecked(): void {
    $this->configureXrpl();
    $this->container->get('audit_chain.logger')->logKeyed('personnel', 'unwitnessed');
    $one = str_repeat('ab', 32);
    $two = str_repeat('cd', 32);
    $this->scriptTransactions([
      $this->witnessPayment($one, 42),
      $this->witnessPayment($two, 42),
    ]);

    $run = $this->container->get('audit_chain.scheduled_verifier')->runNow();
    $this->assertTrue($run['ok']);
    $this->assertSame(RewindDetector::STATUS_UNCHECKED, $run['rewind']['status']);
    $this->assertSame([], $this->captured);
  }

  /**
   * No configured witness means no network read and no rewind result.
   */
  public function testUnconfiguredWitnessDoesNotCallTransport(): void {
    $this->container->get('audit_chain.logger')->logKeyed('personnel', 'local_only');
    $run = $this->container->get('audit_chain.scheduled_verifier')->runNow();
    $this->assertTrue($run['ok']);
    $this->assertSame(RewindDetector::STATUS_NOT_CONFIGURED, $run['rewind']['status']);
    $this->assertSame([], $this->transport->calls);
    $this->assertSame([], $this->captured);
  }

  /**
   * Points the XRPL client at the fixture read service.
   */
  private function configureXrpl(): void {
    $this->config('audit_chain.settings')
      ->set('witness_backend', 'xrpl')
      ->set('witness_xrpl', [
        'relay_url' => 'https://relay.example/witness',
        'read_url' => 'https://read.example',
        'network' => 'xrpl:testnet',
        'sink_address' => self::SINK,
        'witness_account' => self::WITNESS_ACCOUNT,
      ])
      ->save();
  }

  /**
   * Queues one account-transaction list response.
   *
   * @param list<array<string, mixed>> $transactions
   *   Transaction objects the read service would return.
   */
  private function scriptTransactions(array $transactions): void {
    $this->transport->script[] = [
      'status' => 200,
      'body' => json_encode(['transactions' => $transactions], JSON_THROW_ON_ERROR),
    ];
  }

  /**
   * Builds one validated one-drop witness payment.
   *
   * @param string $digest
   *   Lowercase checkpoint digest.
   * @param int $ledgerIndex
   *   Ledger index.
   *
   * @return array<string, mixed>
   *   Transaction object.
   */
  private function witnessPayment(string $digest, int $ledgerIndex): array {
    return [
      'validated' => TRUE,
      'ledger_index' => $ledgerIndex,
      'TransactionType' => 'Payment',
      'Account' => self::WITNESS_ACCOUNT,
      'Destination' => self::SINK,
      'Amount' => '1',
      'Fee' => '12',
      'meta' => ['TransactionResult' => 'tesSUCCESS'],
      'Memos' => [[
        'Memo' => [
          'MemoType' => bin2hex('audit_chain.checkpoint.v1'),
          'MemoData' => bin2hex((string) hex2bin($digest)),
        ],
      ],
      ],
    ];
  }

  /**
   * Loads the chain columns a verification check must not rewrite.
   *
   * @return list<array<string, int|string|null>>
   *   Rows in id order.
   */
  private function chainSnapshot(): array {
    $rows = [];
    $result = $this->container->get('database')->select('audit_chain_log', 'l')
      ->fields('l', ['id', 'operation', 'prev_hash', 'row_hash'])
      ->orderBy('id')
      ->execute();
    foreach ($result as $row) {
      $rows[] = [
        'id' => (int) $row->id,
        'operation' => (string) $row->operation,
        'prev_hash' => $row->prev_hash === NULL ? NULL : (string) $row->prev_hash,
        'row_hash' => $row->row_hash === NULL ? NULL : (string) $row->row_hash,
      ];
    }
    return $rows;
  }

  /**
   * Returns runtime requirements keyed by requirement id.
   *
   * @return array<string, array<string, mixed>>
   *   hook_requirements() runtime results.
   */
  private function runtimeRequirements(): array {
    $this->container->get('module_handler')->loadInclude('audit_chain', 'install');
    return audit_chain_requirements('runtime');
  }

}

/**
 * HTTP double that returns scripted results and records calls.
 */
final class RewindScriptTransport implements WitnessTransportInterface {

  /**
   * Recorded requests.
   *
   * @var list<array{method: string, url: string, body: string, headers: array<string, string>}>
   */
  public array $calls = [];

  /**
   * Scripted results.
   *
   * @var list<array{status: int, body: string}>
   */
  public array $script = [];

  /**
   * {@inheritdoc}
   */
  public function request(string $method, string $url, string $body, array $headers, int $maxBytes = 10000): array {
    $this->calls[] = [
      'method' => $method,
      'url' => $url,
      'body' => $body,
      'headers' => $headers,
    ];
    if ($this->script === []) {
      throw new \RuntimeException('unexpected_witness_request');
    }
    $next = array_shift($this->script);
    if (strlen($next['body']) > $maxBytes) {
      throw new \RuntimeException('response_too_large');
    }
    return $next;
  }

}

/**
 * DNS double keyed by hostname.
 */
final class RewindMapDns implements WitnessDnsResolverInterface {

  /**
   * Stores the hostname map.
   *
   * @param array<string, list<string>> $map
   *   Hostnames to the addresses a lookup would return.
   */
  public function __construct(
    private array $map,
  ) {}

  /**
   * {@inheritdoc}
   */
  public function resolve(string $host): array {
    if (!array_key_exists($host, $this->map)) {
      throw new \RuntimeException('dns_unmapped');
    }
    return $this->map[$host];
  }

}
