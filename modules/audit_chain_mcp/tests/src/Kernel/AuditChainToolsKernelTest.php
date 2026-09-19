<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain_mcp\Kernel;

use Drupal\audit_chain\AuditChainLogger;
use Drupal\audit_chain\AuditChainMetrics;
use Drupal\audit_chain\EvidenceExporter;
use Drupal\audit_chain\ScheduledVerifier;
use Drupal\Core\Session\AnonymousUserSession;
use Drupal\key\Entity\Key;
use Drupal\KernelTests\KernelTestBase;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;

/**
 * Exercises discovery and direct execution against source governance.
 *
 * @group audit_chain
 *
 * @runTestsInSeparateProcesses
 */
#[Group('audit_chain')]
#[RunTestsInSeparateProcesses]
final class AuditChainToolsKernelTest extends KernelTestBase {

  use UserCreationTrait;

  private const KEY_ID = 'chain_key_7q';

  private const KEY_VALUE = 'hmac-material-that-must-never-leave-7Q';

  private const IP = '203.0.113.77';

  private const USER_AGENT = 'PrivateBrowser-7Q/9.9';

  private const METADATA = 'metadata-note-7Q';

  private const LABEL = 'entity-label-7Q';

  private const SEAL_REASON = 'seal-reason-free-text-7Q';

  private const DESTINATION = 'https://ingest-user:ingest-pass-7Q@evidence.example.com:8443/services/collector-7Q?token=query-token-7Q';

  private const READ_TOOLS = [
    'audit_chain_status',
    'audit_chain_window_counts',
    'audit_chain_export_status',
  ];

  private const VERIFY = 'audit_chain_verify_now';

  /**
   * Last row id under the seal.
   */
  private int $sealedThrough = 0;

  /**
   * Row id of the seeded keyed entry, past the seal.
   */
  private int $keyedRow = 0;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system', 'user', 'field', 'filter', 'text', 'file', 'node',
    'serialization', 'jsonapi', 'tool', 'key', 'image', 'options',
    'path_alias', 'consumers', 'simple_oauth', 'encrypt', 'audit_chain',
    'mcp_sentinel', 'audit_chain_mcp',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    // Tool API and MCP Sentinel are optional. Where a pipeline does not
    // install them, skip instead of failing on a missing module.
    if (!class_exists('Drupal\\tool\\Tool\\ToolBase') || !class_exists('Drupal\\mcp_sentinel\\Plugin\\tool\\Tool\\McpGovernedToolBase')) {
      $this->markTestSkipped('Tool API and MCP Sentinel are not installed.');
    }
    parent::setUp();
    $this->installSchema('audit_chain', [
      'audit_chain_log',
      'audit_chain_mutex',
      'audit_chain_recovery',
    ]);
    $this->container->get('database')->insert('audit_chain_mutex')
      ->fields(['id' => 1, 'locked' => 1])->execute();
    $this->installEntitySchema('user');
    $this->installConfig(['system', 'user', 'audit_chain', 'mcp_sentinel']);

    $role = Role::load('mcp_api') ?? Role::create(['id' => 'mcp_api', 'label' => 'MCP API']);
    $role->grantPermission('access mcp sentinel context')
      ->grantPermission('use audit chain mcp tools')
      ->save();
    $this->config('mcp_sentinel.settings')->set('governed_role_fallback', TRUE)->save();
    $this->setUpCurrentUser(['roles' => ['mcp_api']]);
  }

  /**
   * Read tools run for a governed account and refuse an anonymous one.
   */
  public function testGovernedToolsAndAnonymousDenial(): void {
    $account = $this->container->get('current_user')->getAccount();
    foreach (self::READ_TOOLS as $id) {
      $this->container->get('current_user')->setAccount($account);
      $tool = $this->tool($id);
      self::assertTrue($tool->discoveryAccess($account)->isAllowed(), $id);
      self::assertTrue($tool->access(), $id);
      $tool->execute();
      self::assertTrue($tool->getResultStatus(), $id . ': ' . $tool->getResultMessage());
      self::assertNotEmpty($tool->getResult()->getContextValues(), $id);

      $this->container->get('current_user')->setAccount(new AnonymousUserSession());
      $denied = $this->tool($id);
      self::assertFalse($denied->discoveryAccess(new AnonymousUserSession())->isAllowed(), $id);
      self::assertFalse($denied->access(), $id);
      $denied->execute();
      self::assertFalse($denied->getResultStatus(), $id);
      self::assertEmpty($denied->getResult()->getContextValues(), $id);
    }
  }

  /**
   * Sentinel access alone does not grant the module's tools.
   */
  public function testModulePermissionIsRequired(): void {
    Role::load('mcp_api')->revokePermission('use audit chain mcp tools')
      ->grantPermission('run audit chain verification via mcp')->save();
    $account = $this->container->get('current_user');
    foreach ([...self::READ_TOOLS, self::VERIFY] as $id) {
      $tool = $this->tool($id);
      self::assertFalse($tool->discoveryAccess($account)->isAllowed(), $id);
      self::assertFalse($tool->access(), $id);
      $tool->execute();
      self::assertFalse($tool->getResultStatus(), $id);
      self::assertEmpty($tool->getResult()->getContextValues(), $id);
    }
    self::assertNull($this->container->get('state')->get(ScheduledVerifier::STATE_KEY));
  }

  /**
   * Disabled auditing makes governance not ready, so every tool refuses.
   */
  public function testGovernanceNotReadyRefusesDirectExecution(): void {
    Role::load('mcp_api')->grantPermission('run audit chain verification via mcp')->save();
    $this->config('mcp_sentinel.settings')->set('audit_enabled', FALSE)->save();
    foreach ([...self::READ_TOOLS, self::VERIFY] as $id) {
      $tool = $this->tool($id);
      self::assertFalse($tool->discoveryAccess($this->container->get('current_user'))->isAllowed(), $id);
      self::assertFalse($tool->access(), $id);
      $tool->execute();
      self::assertFalse($tool->getResultStatus(), $id);
      self::assertEmpty($tool->getResult()->getContextValues(), $id);
    }
    self::assertNull($this->container->get('state')->get(ScheduledVerifier::STATE_KEY));
  }

  /**
   * Status reports the verdict, signing, seal position and nothing secret.
   */
  public function testStatusReportsHealthWithoutKeyOrSealMaterial(): void {
    $this->config('audit_chain.settings')->set('verify_interval', 3600)->save();
    $status = $this->execute('audit_chain_status');
    self::assertSame('warn', $status['verification']['status']);
    self::assertSame('pending', $status['verification']['reason']);
    self::assertNull($status['last_run']);
    self::assertFalse($status['signing']['keyed']);
    self::assertNull($status['seal']);
    self::assertNull($status['recovery']);

    $this->seedSealedChain();
    $this->container->get('audit_chain.scheduled_verifier')->runNow();
    $this->rebuildMetrics();

    $status = $this->execute('audit_chain_status');
    self::assertSame('ok', $status['verification']['status']);
    self::assertSame('passing', $status['verification']['reason']);
    self::assertGreaterThanOrEqual(3, $status['verification']['rows']);
    self::assertTrue($status['last_run']['ok']);
    self::assertTrue($status['last_run']['keyed']);
    self::assertSame($this->sealedThrough, $status['last_run']['sealed_through']);
    self::assertTrue($status['last_run']['seal_intact']);
    self::assertSame(['keyed' => TRUE], $status['signing']);
    self::assertSame($this->sealedThrough, $status['seal']['sealed_through_id']);
    self::assertSame($this->sealedThrough, $status['seal']['row_count']);
    self::assertSame(['sealed_through_id', 'row_count', 'sealed_at'], array_keys($status['seal']));
    $this->assertNothingSensitive($status);
  }

  /**
   * Window counts split keyed from unkeyed and refuse an unknown window.
   */
  public function testWindowCountsForTheFixedWindows(): void {
    $definition = $this->tool('audit_chain_window_counts')->getPluginDefinition();
    $constraints = $definition->getInputDefinitions()['window']->getConstraints();
    self::assertSame(AuditChainMetrics::windows(), $constraints['Choice']['choices']);

    $this->seedSealedChain();
    $expected = $this->countRows();

    $all = $this->execute('audit_chain_window_counts');
    self::assertSame(AuditChainMetrics::windows(), array_keys($all['windows']));
    self::assertSame($this->sealedThrough, $all['windows']['24h']['unkeyed']);
    self::assertGreaterThanOrEqual(1, $all['windows']['24h']['keyed']);
    self::assertGreaterThanOrEqual($expected, $all['windows']['30d']['total']);
    self::assertSame(
      $all['windows']['7d']['total'],
      $all['windows']['7d']['keyed'] + $all['windows']['7d']['unkeyed'],
    );

    $one = $this->execute('audit_chain_window_counts', ['window' => '7d']);
    self::assertSame(['7d'], array_keys($one['windows']));
    $this->assertNothingSensitive($all + ['one' => $one]);

    // Tool API may reject a value when it is set. Count the cases that reach
    // execute(), so this cannot pass without ever asserting a refusal.
    $reached = 0;
    foreach (['bogus-window-7Q', '1d', '24h 7Q'] as $window) {
      $reached += (int) $this->assertRefused('audit_chain_window_counts', ['window' => $window]);
    }
    self::assertGreaterThanOrEqual(1, $reached);
  }

  /**
   * Export status shows the checkpoint and backlog, never the destination URL.
   */
  public function testExportStatusRedactsTheDestination(): void {
    $status = $this->execute('audit_chain_export_status');
    self::assertFalse($status['enabled']);
    self::assertFalse($status['configured']);
    self::assertNull($status['destination']);
    self::assertNull($status['checkpoint']);
    self::assertNull($status['waiting']);

    $this->seedSealedChain();
    $this->config('audit_chain.settings')
      ->set('export_enabled', TRUE)
      ->set('export_destination', self::DESTINATION)
      ->set('export_channel', 'seed')
      ->save();
    $first = (int) $this->container->get('database')->select('audit_chain_log', 'l')
      ->fields('l', ['id'])->condition('channel', 'seed')->orderBy('id')
      ->range(0, 1)->execute()->fetchField();
    $this->container->get('state')->set(
      EvidenceExporter::CHECKPOINT_PREFIX . sha1(self::DESTINATION),
      ['last_id' => $first, 'time' => 1700000000, 'destination' => 'ignored'],
    );

    $status = $this->execute('audit_chain_export_status');
    self::assertTrue($status['enabled']);
    self::assertTrue($status['configured']);
    self::assertSame(['kind' => 'https', 'host' => 'evidence.example.com'], $status['destination']);
    self::assertSame(['last_id' => $first, 'time' => 1700000000], $status['checkpoint']);
    // Two of the three rows on the "seed" channel are past the checkpoint.
    // MCP Sentinel's own rows are on another channel and are filtered out.
    self::assertTrue($status['channel_filtered']);
    self::assertSame('seed', $status['channel']);
    self::assertSame(2, $status['waiting']);
    $json = json_encode($status);
    foreach (['7Q', 'ingest-user', 'collector', 'token', '8443'] as $forbidden) {
      self::assertStringNotContainsString($forbidden, $json, $forbidden);
    }

    $this->config('audit_chain.settings')
      ->set('export_destination', '/var/evidence-7Q/chain.ndjson')
      ->set('export_channel', 'Not A Machine Name 7Q')->save();
    $status = $this->execute('audit_chain_export_status');
    self::assertTrue($status['channel_filtered']);
    self::assertNull($status['channel']);
    self::assertSame(['kind' => 'file', 'host' => NULL], $status['destination']);
    self::assertSame(['last_id' => 0, 'time' => NULL], $status['checkpoint']);
    self::assertStringNotContainsString('7Q', json_encode($status));
  }

  /**
   * Verify now needs its own permission on top of the read permission.
   */
  public function testVerifyNowNeedsItsOwnPermission(): void {
    $account = $this->container->get('current_user');
    $tool = $this->tool(self::VERIFY);
    self::assertFalse($tool->discoveryAccess($account)->isAllowed());
    self::assertFalse($tool->access());
    $tool->execute();
    self::assertFalse($tool->getResultStatus());
    self::assertEmpty($tool->getResult()->getContextValues());
    self::assertNull($this->container->get('state')->get(ScheduledVerifier::STATE_KEY));

    Role::load('mcp_api')->grantPermission('run audit chain verification via mcp')->save();
    $tool = $this->tool(self::VERIFY);
    self::assertTrue($tool->discoveryAccess($account)->isAllowed());
    self::assertTrue($tool->access());
  }

  /**
   * An intact chain passes, and the run is recorded like a scheduled one.
   */
  public function testVerifyNowPassesIntactChain(): void {
    Role::load('mcp_api')->grantPermission('run audit chain verification via mcp')->save();
    $this->seedSealedChain();

    $verdict = $this->execute(self::VERIFY);
    self::assertTrue($verdict['ran']);
    self::assertTrue($verdict['ok']);
    self::assertNull($verdict['reason']);
    self::assertTrue($verdict['keyed']);
    self::assertNull($verdict['broken_at']);
    self::assertSame(0, $verdict['unkeyed_rows']);
    self::assertSame($this->sealedThrough, $verdict['sealed_through']);
    self::assertTrue($verdict['seal_intact']);
    self::assertSame($this->sealedThrough + 1, $verdict['verified_from']);
    self::assertNull($verdict['successor']);
    $this->assertNothingSensitive($verdict);

    $run = $this->container->get('state')->get(ScheduledVerifier::STATE_KEY);
    self::assertTrue($run['ok']);
  }

  /**
   * A broken chain fails with the row id only, and is never rewritten.
   */
  public function testVerifyNowFailsBrokenChain(): void {
    Role::load('mcp_api')->grantPermission('run audit chain verification via mcp')->save();
    $this->seedSealedChain();
    $database = $this->container->get('database');
    $database->update('audit_chain_log')
      ->fields(['operation' => 'forged-operation-7Q'])
      ->condition('id', $this->keyedRow)
      ->execute();
    $before = $database->select('audit_chain_log', 'l')->fields('l', ['id', 'row_hash'])
      ->condition('id', $this->keyedRow, '<=')->orderBy('id')->execute()->fetchAllKeyed();

    $verdict = $this->execute(self::VERIFY);
    self::assertTrue($verdict['ran']);
    self::assertFalse($verdict['ok']);
    self::assertSame(AuditChainLogger::REASON_TAMPERED, $verdict['reason']);
    self::assertSame($this->keyedRow, $verdict['broken_at']);
    $this->assertNothingSensitive($verdict);
    self::assertStringNotContainsString('forged-operation', json_encode($verdict));

    $after = $database->select('audit_chain_log', 'l')->fields('l', ['id', 'row_hash'])
      ->condition('id', $this->keyedRow, '<=')->orderBy('id')->execute()->fetchAllKeyed();
    self::assertSame($before, $after);
    $run = $this->container->get('state')->get(ScheduledVerifier::STATE_KEY);
    self::assertFalse($run['ok']);

    // Classification needs a schedule: with none it reports "disabled".
    $this->config('audit_chain.settings')->set('verify_interval', 3600)->save();
    $this->rebuildMetrics();
    $status = $this->execute('audit_chain_status');
    self::assertSame('crit', $status['verification']['status']);
    self::assertSame(AuditChainLogger::REASON_TAMPERED, $status['last_run']['reason']);
    self::assertSame($this->keyedRow, $status['last_run']['broken_at']);
  }

  /**
   * A second call inside the minimum interval does not walk the table again.
   */
  public function testVerifyNowDoesNotRewalkInsideTheMinimumInterval(): void {
    Role::load('mcp_api')->grantPermission('run audit chain verification via mcp')->save();
    $this->seedSealedChain();
    $first = $this->execute(self::VERIFY);
    self::assertTrue($first['ran']);
    self::assertTrue($first['ok']);

    // Break the chain. A fresh walk would now fail, so a passing answer proves
    // the stored verdict was returned instead.
    $this->container->get('database')->update('audit_chain_log')
      ->fields(['operation' => 'forged'])->condition('id', $this->keyedRow)->execute();
    $second = $this->execute(self::VERIFY);
    self::assertFalse($second['ran']);
    self::assertTrue($second['ok']);

    $run = $this->container->get('state')->get(ScheduledVerifier::STATE_KEY);
    $run['time'] -= 3600;
    $this->container->get('state')->set(ScheduledVerifier::STATE_KEY, $run);
    $third = $this->execute(self::VERIFY);
    self::assertTrue($third['ran']);
    self::assertFalse($third['ok']);
  }

  /**
   * Stored free text and unknown keys never pass through to a result.
   *
   * The run record is state. A later version, another module or a restored
   * database can put anything in it.
   */
  public function testStoredFreeTextNeverPassesThrough(): void {
    Role::load('mcp_api')->grantPermission('run audit chain verification via mcp')->save();
    $now = $this->container->get('datetime.time')->getRequestTime();
    $this->container->get('state')->set(ScheduledVerifier::STATE_KEY, [
      'time' => $now,
      'ok' => FALSE,
      'reason' => 'free text reason 7Q',
      'keyed' => TRUE,
      'operator_note' => 'note-7Q',
      'verdict' => [
        'ok' => FALSE,
        'broken_at' => 4,
        'reason' => 'free text reason 7Q',
        'unkeyed_rows' => 0,
        'row' => ['ip_address' => self::IP, 'metadata' => self::METADATA],
      ],
      'successor' => [
        'segment_ok' => FALSE,
        'historical_ok' => FALSE,
        'reason' => 'successor_integrity_failed',
        'segment_id' => 'segment-7Q',
        'incident' => 'INC-7Q operator text',
        'historical_verdict' => ['reason' => 'tampered-7Q'],
        'verified_rows' => 9,
      ],
    ]);

    // Inside the minimum interval, so verify now returns this stored run.
    $results = [
      $this->execute('audit_chain_status'),
      $this->execute(self::VERIFY),
    ];
    self::assertFalse($results[1]['ran']);
    foreach ([$results[0]['last_run'], $results[1]] as $run) {
      self::assertFalse($run['ok']);
      self::assertSame('other', $run['reason']);
      self::assertSame(4, $run['broken_at']);
    }
    $expected = [
      'segment_ok' => FALSE,
      'historical_ok' => FALSE,
      'reason' => 'successor_integrity_failed',
      'verified_rows' => 9,
    ];
    self::assertSame($expected, $results[0]['recovery']);
    self::assertSame($expected, $results[1]['successor']);
    $json = json_encode($results);
    foreach (['7Q', self::IP, 'operator_note', 'incident', 'segment_id', 'historical_verdict'] as $forbidden) {
      self::assertStringNotContainsString($forbidden, $json, $forbidden);
    }
  }

  /**
   * Creates a fresh tool instance.
   */
  private function tool(string $id): object {
    return $this->container->get('plugin.manager.tool')->createInstance($id);
  }

  /**
   * Runs a tool that must succeed and returns its result.
   */
  private function execute(string $id, array $inputs = []): array {
    $tool = $this->tool($id);
    foreach ($inputs as $name => $value) {
      $tool->setInputValue($name, $value);
    }
    self::assertTrue($tool->access(), $id);
    $tool->execute();
    self::assertTrue($tool->getResultStatus(), $id . ': ' . $tool->getResultMessage());
    return $tool->getResult()->getContextValues();
  }

  /**
   * Asserts a tool refuses the inputs without echoing them.
   *
   * @return bool
   *   TRUE when execute() ran and the refusal was asserted, FALSE when Tool
   *   API rejected the value before that.
   */
  private function assertRefused(string $id, array $inputs): bool {
    $tool = $this->tool($id);
    try {
      foreach ($inputs as $name => $value) {
        $tool->setInputValue($name, $value);
      }
      $tool->execute();
    }
    catch (\Throwable) {
      // A typed-data refusal at input time is as good as one at execute.
      return FALSE;
    }
    self::assertFalse($tool->getResultStatus(), json_encode($inputs));
    self::assertStringNotContainsString('7Q', (string) $tool->getResultMessage());
    self::assertEmpty($tool->getResult()->getContextValues());
    return TRUE;
  }

  /**
   * Two unkeyed rows, a key, one keyed row, and a seal over the unkeyed two.
   *
   * Every row carries a recognisable IP address, user agent, label and
   * metadata value. None of them may reach a tool result.
   */
  private function seedSealedChain(): void {
    $stack = $this->container->get('request_stack');
    $stack->push(Request::create('/', 'GET', [], [], [], [
      'REMOTE_ADDR' => self::IP,
      'HTTP_USER_AGENT' => self::USER_AGENT,
    ]));
    $chain = $this->container->get('audit_chain.logger');
    $metadata = ['note' => self::METADATA, 'label' => self::LABEL];
    $chain->log('seed', 'first', $metadata);
    $chain->log('seed', 'second', $metadata);
    Key::create([
      'id' => self::KEY_ID,
      'label' => self::KEY_ID,
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => self::KEY_VALUE],
    ])->save();
    $this->config('audit_chain.settings')->set('hash_key', self::KEY_ID)->save();
    $chain->log('seed', 'third', $metadata);
    $this->keyedRow = $this->maxRowId();
    // MCP Sentinel audits the key and config saves above. Its rows written
    // before the key resolved are unkeyed too, so seal through the last one.
    $unkeyed = $this->container->get('database')->select('audit_chain_log', 'l')
      ->condition('key_id', '');
    $unkeyed->addExpression('MAX(id)');
    $this->sealedThrough = (int) $unkeyed->execute()->fetchField();
    self::assertGreaterThanOrEqual(2, $this->sealedThrough);
    self::assertGreaterThan($this->sealedThrough, $this->keyedRow);
    $sealed = $chain->sealPrefix($this->sealedThrough, self::SEAL_REASON);
    self::assertTrue($sealed['sealed'], (string) $sealed['message']);
    $stack->pop();

    $row = $this->container->get('database')->select('audit_chain_log', 'l')
      ->fields('l')->condition('id', $this->keyedRow)->execute()->fetchAssoc();
    self::assertSame(self::IP, $row['ip_address']);
    self::assertSame(self::USER_AGENT, $row['user_agent']);
    self::assertStringContainsString(self::METADATA, (string) $row['metadata']);
  }

  /**
   * Highest row id in the chain.
   */
  private function maxRowId(): int {
    $query = $this->container->get('database')->select('audit_chain_log', 'l');
    $query->addExpression('MAX(id)');
    return (int) $query->execute()->fetchField();
  }

  /**
   * Rows currently in the chain.
   */
  private function countRows(): int {
    return (int) $this->container->get('database')->select('audit_chain_log', 'l')
      ->countQuery()->execute()->fetchField();
  }

  /**
   * Drops the metrics service so its per-request cache starts empty.
   */
  private function rebuildMetrics(): void {
    $this->container->set('audit_chain.metrics', NULL);
  }

  /**
   * Asserts no key, MAC, digest, hash or personal data is in a result.
   */
  private function assertNothingSensitive(array $values): void {
    $json = json_encode($values);
    $seal = $this->container->get('audit_chain.logger')->getSeal();
    self::assertNotNull($seal);
    $forbidden = [
      self::KEY_VALUE, self::KEY_ID, self::IP, self::USER_AGENT,
      self::METADATA, self::LABEL, self::SEAL_REASON,
      $seal['seal_mac'], $seal['prefix_digest'], '7Q',
    ];
    $hashes = $this->container->get('database')->select('audit_chain_log', 'l')
      ->fields('l', ['row_hash'])->execute()->fetchCol();
    foreach ([...$forbidden, ...$hashes] as $value) {
      self::assertStringNotContainsString((string) $value, $json);
    }
    $columns = [
      'seal_mac', 'prefix_digest', 'key_id', 'row_hash', 'prev_hash',
      'metadata', 'ip_address', 'user_agent', 'uid',
    ];
    foreach ($columns as $key) {
      self::assertStringNotContainsString('"' . $key . '"', $json, $key);
    }
  }

}
