<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\key\Entity\Key;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel tests for the off-system evidence export (d.o #3616535, part 2).
 *
 * Local-only evidence does not leave the writer's trust boundary. The contract
 * under test: verified chain rows export as versioned, data-minimized NDJSON
 * to an independently controlled destination, with per-destination checkpoint
 * semantics — a failed delivery leaves the checkpoint for retry (at-least-once,
 * duplicates possible and documented), replay re-emits history without moving
 * the checkpoint backwards, and a failing scheduled verification blocks export
 * so unverified evidence is never presented as verified.
 *
 * @group audit_chain
 *
 * @runTestsInSeparateProcesses
 */
#[Group('audit_chain')]
#[RunTestsInSeparateProcesses]
final class AuditChainEvidenceExporterTest extends KernelTestBase {

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
    $this->installConfig(['system', 'audit_chain']);

    Key::create([
      'id' => 'chain_key',
      'label' => 'chain_key',
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => 'secret-hmac-material'],
    ])->save();
    $this->config('audit_chain.settings')->set('hash_key', 'chain_key')->save();
  }

  /**
   * Writes $count chain rows on a channel.
   */
  private function writeRows(int $count, string $channel = 'personnel'): void {
    $logger = \Drupal::service('audit_chain.logger');
    for ($i = 0; $i < $count; $i++) {
      $logger->log($channel, 'field_read', ['id' => (string) $i, 'secret_note' => 'metadata-payload']);
    }
  }

  /**
   * A file URI in the test's temp directory.
   */
  private function destination(string $name = 'evidence.ndjson'): string {
    return 'file://' . $this->siteDirectory . '/' . $name;
  }

  /**
   * Reads exported NDJSON lines (excluding the batch header lines).
   */
  private function exportedRows(string $name = 'evidence.ndjson'): array {
    $path = str_replace('file://', '', $this->destination($name));
    if (!file_exists($path)) {
      return [];
    }
    $rows = [];
    foreach (array_filter(explode("\n", (string) file_get_contents($path))) as $line) {
      $decoded = json_decode($line, TRUE);
      if (isset($decoded['id'])) {
        $rows[] = $decoded;
      }
    }
    return $rows;
  }

  /**
   * Export delivers new rows, checkpoints, and resumes with only new rows.
   */
  public function testExportCheckpointsAndResumes(): void {
    $this->writeRows(3);
    $exporter = \Drupal::service('audit_chain.evidence_exporter');

    $run = $exporter->exportTo($this->destination());
    $this->assertTrue($run['ok'], 'A healthy chain must export.');
    $this->assertSame(3, $run['delivered']);
    $this->assertCount(3, $this->exportedRows());

    $this->writeRows(2);
    $run = $exporter->exportTo($this->destination());
    $this->assertSame(2, $run['delivered'],
      'A second export must deliver only rows after the checkpoint.');
    $this->assertCount(5, $this->exportedRows());
  }

  /**
   * Replay re-emits from a requested id without moving the checkpoint back.
   */
  public function testReplayReEmitsWithoutMovingCheckpointBackwards(): void {
    $this->writeRows(3);
    $exporter = \Drupal::service('audit_chain.evidence_exporter');
    $exporter->exportTo($this->destination());

    $replay = $exporter->exportTo($this->destination('replay.ndjson'), 1);
    $this->assertSame(3, $replay['delivered'],
      'Replay from id 1 must re-emit the full history.');

    $this->writeRows(1);
    $run = $exporter->exportTo($this->destination());
    $this->assertSame(1, $run['delivered'],
      'The primary checkpoint must be unaffected by a replay to another destination.');
  }

  /**
   * The export is data-minimized and versioned.
   */
  public function testExportIsDataMinimizedAndVersioned(): void {
    $this->writeRows(1);
    \Drupal::service('audit_chain.evidence_exporter')->exportTo($this->destination());

    $rows = $this->exportedRows();
    $this->assertCount(1, $rows);
    $row = $rows[0];
    foreach (['id', 'channel', 'operation', 'timestamp', 'uid', 'prev_hash', 'row_hash', 'contract_version'] as $key) {
      $this->assertArrayHasKey($key, $row, "Exported rows must carry '$key'.");
    }
    foreach (['metadata', 'ip_address', 'user_agent', 'entity_label'] as $key) {
      $this->assertArrayNotHasKey($key, $row, "Exported rows must NOT carry '$key' (data minimization).");
    }

    $raw = (string) file_get_contents(str_replace('file://', '', $this->destination()));
    $this->assertStringNotContainsString('metadata-payload', $raw,
      'Row metadata payloads must never leave the system.');
    $this->assertStringNotContainsString('secret-hmac-material', $raw,
      'Signing key material must never leave the system.');
  }

  /**
   * Channel filtering keeps partitions separate.
   */
  public function testChannelPartitionFilter(): void {
    $this->writeRows(2, 'personnel');
    $this->writeRows(3, 'finance');

    \Drupal::service('audit_chain.evidence_exporter')
      ->exportTo($this->destination(), NULL, 'finance');

    $rows = $this->exportedRows();
    $this->assertCount(3, $rows);
    foreach ($rows as $row) {
      $this->assertSame('finance', $row['channel'],
        'A channel-filtered export must contain only that partition.');
    }
  }

  /**
   * A failed delivery leaves the checkpoint so the next run retries.
   */
  public function testDestinationOutageLeavesCheckpointForRetry(): void {
    $this->writeRows(2);
    $exporter = \Drupal::service('audit_chain.evidence_exporter');

    // An unwritable destination: a directory that does not exist.
    $bad = 'file://' . $this->siteDirectory . '/no/such/dir/out.ndjson';
    $run = $exporter->exportTo($bad);
    $this->assertFalse($run['ok'], 'A destination outage must fail the run.');

    // Recovery: the same logical export against a healthy destination
    // delivers everything — nothing was lost to a moved checkpoint.
    $run = $exporter->exportTo($this->destination());
    $this->assertSame(2, $run['delivered'],
      'Recovery after an outage must deliver from the untouched checkpoint.');
  }

  /**
   * At-least-once: a rolled-back checkpoint re-delivers, never skips.
   */
  public function testDuplicateDeliveryIsOverlapNeverGap(): void {
    $this->writeRows(3);
    $exporter = \Drupal::service('audit_chain.evidence_exporter');
    $exporter->exportTo($this->destination());

    // Simulate delivered-but-uncheckpointed: force the checkpoint back. The
    // exporter stores per-destination checkpoints under a deterministic key.
    $state = \Drupal::state();
    $key = 'audit_chain.export_checkpoint.' . sha1($this->destination());
    $checkpoint = $state->get($key);
    $this->assertIsArray($checkpoint, 'Sanity: the checkpoint exists.');
    $state->set($key, ['last_id' => 1] + $checkpoint);

    $run = $exporter->exportTo($this->destination());
    $this->assertSame(2, $run['delivered'],
      'A rolled-back checkpoint must re-deliver the overlap (at-least-once), never skip.');
    $this->assertCount(5, $this->exportedRows(),
      'The destination holds the original three plus the two re-delivered rows.');
  }

  /**
   * A batch limit exports in resumable slices with the remainder reported.
   */
  public function testBatchLimitIsResumable(): void {
    $this->writeRows(5);
    $exporter = \Drupal::service('audit_chain.evidence_exporter');

    $run = $exporter->exportTo($this->destination(), NULL, NULL, 2);
    $this->assertSame(2, $run['delivered']);
    $this->assertSame(3, $run['remaining'],
      'A limited run must report how many rows it did NOT cover.');

    $exporter->exportTo($this->destination(), NULL, NULL, 2);
    $run = $exporter->exportTo($this->destination(), NULL, NULL, 2);
    $this->assertSame(1, $run['delivered']);
    $this->assertSame(0, $run['remaining']);
    $this->assertCount(5, $this->exportedRows(),
      'Successive limited runs must cover the whole backlog exactly once.');
  }

  /**
   * An HTTP destination receives the batch as one NDJSON POST.
   */
  public function testHttpDestinationDelivery(): void {
    $this->writeRows(2);
    $history = [];
    $mock = new MockHandler([new Response(200)]);
    $stack = HandlerStack::create($mock);
    $stack->push(Middleware::history($history));
    $this->container->set('http_client', new Client(['handler' => $stack]));

    $run = \Drupal::service('audit_chain.evidence_exporter')
      ->exportTo('https://evidence.example.test/ingest');

    $this->assertTrue($run['ok']);
    $this->assertSame(2, $run['delivered']);
    $this->assertCount(1, $history, 'The batch is delivered as a single request.');
    $request = $history[0]['request'];
    $this->assertSame('POST', $request->getMethod());
    $body = (string) $request->getBody();
    $lines = array_values(array_filter(explode("\n", $body)));
    $this->assertCount(2, $lines);
    $first = json_decode($lines[0], TRUE);
    $this->assertSame(1, $first['contract_version']);
    $this->assertStringNotContainsString('metadata-payload', $body,
      'The HTTP body is data-minimized like the file export.');
  }

  /**
   * A non-2xx HTTP response fails the run and leaves the checkpoint.
   */
  public function testHttpDestinationFailureLeavesCheckpoint(): void {
    $this->writeRows(2);
    $mock = new MockHandler([
      new Response(500),
      new Response(200),
    ]);
    $this->container->set('http_client', new Client(['handler' => HandlerStack::create($mock)]));
    $exporter = \Drupal::service('audit_chain.evidence_exporter');

    $run = $exporter->exportTo('https://evidence.example.test/ingest');
    $this->assertFalse($run['ok'], 'A non-2xx response must fail the run.');

    $run = $exporter->exportTo('https://evidence.example.test/ingest');
    $this->assertSame(2, $run['delivered'],
      'The retry must deliver everything from the untouched checkpoint.');
  }

  /**
   * A failing scheduled verification blocks export.
   */
  public function testFailingVerificationBlocksExport(): void {
    $this->writeRows(1);
    \Drupal::state()->set('audit_chain.scheduled_verification', [
      'time' => \Drupal::time()->getRequestTime(),
      'ok' => FALSE,
      'reason' => 'tampered',
    ]);

    $run = \Drupal::service('audit_chain.evidence_exporter')->exportTo($this->destination());
    $this->assertFalse($run['ok'],
      'Unverified evidence must never be presented as verified: export refuses while verification fails.');
    $this->assertSame('verification_failing', $run['reason']);
    $this->assertCount(0, $this->exportedRows());
  }

  /**
   * Cron exports new rows when an export destination is configured.
   */
  public function testCronExportsWhenConfigured(): void {
    $this->writeRows(2);
    $this->config('audit_chain.settings')
      ->set('export_enabled', TRUE)
      ->set('export_destination', $this->destination())
      ->save();

    \Drupal::moduleHandler()->invoke('audit_chain', 'cron');
    $this->assertCount(2, $this->exportedRows(),
      'Cron must push new rows to the configured destination.');
  }

}
