<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain\Kernel;

use Drupal\audit_chain\LogRowLookup;
use Drupal\Core\Database\Database;
use Drupal\Core\Site\Settings;
use Drupal\KernelTests\KernelTestBase;
use Drupal\key\Entity\Key;
use PHPUnit\Framework\Attributes\Group;

/**
 * Single-row lookups on the log must not seq-scan or sort on PostgreSQL.
 *
 * Failure mode: Drupal's pgsql driver renders orderBy('id', 'DESC') as
 * "ORDER BY id DESC NULLS LAST". The ascending primary key cannot serve that
 * ordering, so "read the last row" became a full parallel scan plus a sort of
 * audit_chain_log. The append path does that read while it holds the chain
 * mutex, so on a large log every audited event serialized behind a full-table
 * sort.
 *
 * The test disables sequential scans and sorts for its session and runs
 * EXPLAIN on each statement the module issued. A statement that could only
 * be answered by a scan or a sort still shows that node, so it fails here
 * whatever the table size. Ordered full-range reads (an ORDER BY without a
 * LIMIT) read every row in the range anyway and are out of scope.
 *
 * @group audit_chain
 */
#[Group('audit_chain')]
final class LastRowLookupPlanTest extends KernelTestBase {

  use AuditChainSchemaTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['system', 'user', 'key', 'encrypt', 'audit_chain'];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    if ($this->container->get('database')->driver() !== 'pgsql') {
      $this->markTestSkipped('Query-plan checks run on PostgreSQL only.');
    }
    $this->installEntitySchema('user');
    $this->installAuditChainTables();
    $this->installConfig(['audit_chain']);
    new Settings(['audit_chain_instance_id' => 'plan-test-instance'] + Settings::getAll());
    Key::create([
      'id' => 'plan_key',
      'label' => 'Plan test key',
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => 'plan-test-secret'],
    ])->save();
    $this->config('audit_chain.settings')->set('hash_key', 'plan_key')->save();
  }

  /**
   * Appending reads the previous row hash through the primary key.
   */
  public function testAppendReadsPreviousHashThroughIndex(): void {
    $logger = $this->container->get('audit_chain.logger');
    $logger->log('plan', 'seed', ['n' => 0]);

    $statements = $this->captureStatements(function () use ($logger): void {
      $logger->log('plan', 'append', ['n' => 1]);
      $logger->log('plan', 'append', ['n' => 2]);
    });

    $this->assertNoScanOrSort($statements);
    $this->assertTrue($logger->verify()['ok']);
  }

  /**
   * An archive window without an upper bound resolves it through the index.
   */
  public function testArchiveResolvesLatestIdThroughIndex(): void {
    $logger = $this->container->get('audit_chain.logger');
    for ($n = 0; $n < 3; $n++) {
      $logger->log('plan', 'seed', ['n' => $n]);
    }

    $bundle = NULL;
    $statements = $this->captureStatements(function () use (&$bundle): void {
      $bundle = $this->container->get('audit_chain.archive_bundle_exporter')->create();
    });

    $this->assertSame(3, $bundle['manifest']['window']['through_id'] ?? NULL);
    $this->assertNoScanOrSort($statements);
  }

  /**
   * Bounded and chained-only lookups also stay on the primary key.
   *
   * These shapes back the sealed-prefix verification start, the rewind
   * comparison and the chain-gap fork check.
   */
  public function testBoundedLookupsUseIndex(): void {
    $logger = $this->container->get('audit_chain.logger');
    for ($n = 0; $n < 4; $n++) {
      $logger->log('plan', 'seed', ['n' => $n]);
    }
    $database = $this->container->get('database');

    $results = [];
    $statements = $this->captureStatements(function () use ($database, &$results): void {
      $results[] = LogRowLookup::lastId($database);
      $results[] = LogRowLookup::lastId($database, 3, TRUE);
      $results[] = LogRowLookup::firstIdAfter($database, 2);
      $results[] = LogRowLookup::firstIdAfter($database, 4);
    });

    $this->assertSame([4, 3, 3, NULL], $results);
    $this->assertNoScanOrSort($statements);
  }

  /**
   * Runs a callback and returns the SELECTs it issued against the log table.
   *
   * @return list<array{query: string, args: array}>
   *   Logged statements.
   */
  private function captureStatements(callable $callback): array {
    $key = 'audit_chain_plan_' . $this->randomMachineName();
    Database::startLog($key);
    $callback();
    $logged = Database::getLog($key);

    $statements = [];
    foreach ($logged as $entry) {
      $sql = (string) $entry['query'];
      if (!preg_match('/^\s*SELECT\b/i', $sql) || !preg_match('/audit_chain_log\b/', $sql)) {
        continue;
      }
      // Ordered full-range reads (verification, export rows) are not lookups.
      if (preg_match('/\bORDER BY\b/i', $sql) && !preg_match('/\bLIMIT\b/i', $sql)) {
        continue;
      }
      $statements[] = ['query' => $sql, 'args' => (array) $entry['args']];
    }
    $this->assertNotEmpty($statements, 'The exercised path issued no single-row lookup on audit_chain_log.');
    return $statements;
  }

  /**
   * Fails when any statement's plan scans or sorts audit_chain_log.
   *
   * @param list<array{query: string, args: array}> $statements
   *   Statements captured by captureStatements().
   */
  private function assertNoScanOrSort(array $statements): void {
    $database = $this->container->get('database');
    $database->query('SET enable_seqscan = off');
    $database->query('SET enable_sort = off');
    try {
      foreach ($statements as $statement) {
        $json = $database->query('EXPLAIN (FORMAT JSON) ' . $statement['query'], $statement['args'])->fetchField();
        $plan = json_decode((string) $json, TRUE, 512, JSON_THROW_ON_ERROR);
        $bad = $this->scanOrSortNodes($plan[0]['Plan']);
        $this->assertSame([], $bad, sprintf(
          "Plan scans or sorts the log table:\n%s\nNodes: %s",
          $statement['query'],
          implode(', ', $bad),
        ));
      }
    }
    finally {
      $database->query('RESET enable_seqscan');
      $database->query('RESET enable_sort');
    }
  }

  /**
   * Walks a JSON plan and lists Seq Scan and Sort nodes.
   *
   * @return list<string>
   *   Offending node descriptions.
   */
  private function scanOrSortNodes(array $node): array {
    $bad = [];
    $type = (string) ($node['Node Type'] ?? '');
    if (in_array($type, ['Sort', 'Incremental Sort'], TRUE)) {
      $bad[] = $type;
    }
    if ($type === 'Seq Scan' && str_ends_with((string) ($node['Relation Name'] ?? ''), 'audit_chain_log')) {
      $bad[] = 'Seq Scan on ' . $node['Relation Name'];
    }
    foreach ($node['Plans'] ?? [] as $child) {
      $bad = array_merge($bad, $this->scanOrSortNodes($child));
    }
    return $bad;
  }

}
