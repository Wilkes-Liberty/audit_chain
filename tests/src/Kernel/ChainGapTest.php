<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain\Kernel;

use Drupal\audit_chain\AuditChainLogger;
use Drupal\audit_chain\ChainGap;
use Drupal\audit_chain\Controller\AuditChainDashboardController;
use Drupal\audit_chain\EvidenceExporter;
use Drupal\audit_chain\RecoverySegments;
use Drupal\Core\Site\Settings;
use Drupal\KernelTests\KernelTestBase;
use Drupal\key\Entity\Key;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;

/**
 * Records a known gap without a second recovery segment.
 *
 * @group audit_chain
 *
 * @runTestsInSeparateProcesses
 */
#[Group('audit_chain')]
#[RunTestsInSeparateProcesses]
final class ChainGapTest extends KernelTestBase {

  use AuditChainSchemaTrait;

  private const SEGMENT = '957345ba-a0c8-42d5-9dcb-92ba4430a820';

  private const GAP_ID = '6f1e2d3c-4b5a-4678-9abc-def012345678';

  /**
   * The ordinary chain implementation.
   */
  private AuditChainLogger $chain;

  /**
   * The gap workflow under test.
   */
  private ChainGap $gaps;

  /**
   * The explicit successor workflow.
   */
  private RecoverySegments $recovery;

  /**
   * Real directory for archive files. Kernel tests keep site files on vfs://.
   */
  private string $archiveDirectory = '';

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
    $this->archiveDirectory = sys_get_temp_dir() . '/audit-chain-gap-' . bin2hex(random_bytes(8));
    mkdir($this->archiveDirectory);
    $this->installEntitySchema('user');
    $this->installSchema('user', ['users_data']);
    $this->installAuditChainTables();
    $this->installConfig(['system', 'user', 'audit_chain']);
    $this->container->get('router.builder')->rebuild();
    Key::create([
      'id' => 'recovery_key',
      'label' => 'Synthetic recovery key',
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => 'synthetic-recovery-secret'],
    ])->save();
    $this->config('audit_chain.settings')->set('hash_key', 'recovery_key')->save();
    $this->chain = $this->container->get('audit_chain.logger');
    $this->gaps = $this->container->get('audit_chain.chain_gap');
    $this->recovery = $this->container->get('audit_chain.recovery');
  }

  /**
   * {@inheritdoc}
   */
  protected function tearDown(): void {
    if ($this->archiveDirectory !== '' && is_dir($this->archiveDirectory)) {
      foreach (scandir($this->archiveDirectory) ?: [] as $entry) {
        if ($entry === '.' || $entry === '..') {
          continue;
        }
        unlink($this->archiveDirectory . '/' . $entry);
      }
      rmdir($this->archiveDirectory);
    }
    parent::tearDown();
  }

  /**
   * A verifying chain can name an overlapping lost range and still export.
   */
  public function testRecordedGapStaysVerifiableAndExports(): void {
    $recorded = $this->recordCleanGap();
    $rows = $this->rows();
    $this->assertSame(2, $recorded['input']['lost_from_id']);
    $this->assertSame((int) $rows[1]->id, $recorded['input']['lost_from_id']);
    $this->assertNotSame($rows[1]->row_hash, $recorded['archive_head']);
    $this->assertNotSame($rows[2]->row_hash, $recorded['archive_head']);
    $this->assertTrue($this->chain->verify()['ok']);
    $this->assertSame(1, $this->gapCount());

    $again = $this->gaps->record($recorded['input'], $recorded['digest']);
    $this->assertFalse($again['created']);
    $this->assertSame($recorded['id'], $again['id']);
    $this->assertSame(1, $this->gapCount());

    $bad = $recorded['digest'];
    $bad[0] = $bad[0] === '0' ? '1' : '0';
    try {
      $this->gaps->record($recorded['input'], $bad);
      $this->fail('A wrong digest must not append.');
    }
    catch (\InvalidArgumentException $exception) {
      $this->assertStringContainsString('does not match', $exception->getMessage());
    }
    $this->assertSame(1, $this->gapCount());

    $conflict = $recorded['input'];
    $conflict['lost_head_row_hash'] = str_repeat('ef', 32);
    $preparedConflict = $this->gaps->prepare($conflict);
    try {
      $this->gaps->record($conflict, $preparedConflict['snapshot_digest']);
      $this->fail('A reused gap id must not record a different statement.');
    }
    catch (\RuntimeException $exception) {
      $this->assertStringContainsString('different statement', $exception->getMessage());
    }
    $this->assertSame(1, $this->gapCount());
    $this->assertTrue($this->chain->verify()['ok']);

    $dashboard = $this->renderDashboard();
    $this->assertStringContainsString('Documented exception', $dashboard);
    $this->assertStringContainsString('Fork ' . $recorded['input']['fork_id'], $dashboard);
    $this->assertStringContainsString('at row ' . $recorded['id'], $dashboard);
    $this->assertStringContainsString('not rewritten', $dashboard);
    $this->assertStringContainsString('Lost rows 2 through 3', $dashboard);

    $exporter = $this->container->get('audit_chain.evidence_exporter');
    $run = $exporter->exportTo('file://' . $this->siteDirectory . '/gap-evidence.ndjson');
    $this->assertTrue($run['ok']);
    $exported = $this->exportedRows('gap-evidence.ndjson');
    $gapRow = NULL;
    foreach ($exported as $row) {
      $this->assertSame(1, $row['contract_version']);
      $this->assertArrayNotHasKey('metadata', $row);
      $this->assertArrayNotHasKey('ip_address', $row);
      $this->assertArrayNotHasKey('user_agent', $row);
      $this->assertArrayNotHasKey('entity_label', $row);
      if ($row['operation'] === ChainGap::OPERATION) {
        $gapRow = $row;
      }
      else {
        $this->assertArrayNotHasKey('gap', $row);
      }
    }
    $this->assertIsArray($gapRow);
    $this->assertSame($recorded['input'], $gapRow['gap']);

    $check = $this->gaps->checkArchive(
      $recorded['id'],
      $recorded['files']['archive'],
      $recorded['files']['manifest'],
      $recorded['files']['dump'],
    );
    $this->assertTrue($check['ok']);
    $this->assertNull($check['reason']);

    $flipped = $recorded['files']['archive'] . '.flipped';
    $raw = (string) file_get_contents($recorded['files']['archive']);
    $raw[0] = $raw[0] === '{' ? 'x' : '{';
    file_put_contents($flipped, $raw);
    $mismatch = $this->gaps->checkArchive(
      $recorded['id'],
      $flipped,
      $recorded['files']['manifest'],
      $recorded['files']['dump'],
    );
    $this->assertFalse($mismatch['ok']);
    $this->assertSame(ChainGap::REASON_DIGEST_MISMATCH, $mismatch['reason']);

    $url = $this->gaps->checkArchive(
      $recorded['id'],
      'https://example.com/lost.ndjson',
      $recorded['files']['manifest'],
      $recorded['files']['dump'],
    );
    $this->assertSame(ChainGap::REASON_UNREADABLE, $url['reason']);

    $missing = $this->gaps->checkArchive(
      999999,
      $recorded['files']['archive'],
      $recorded['files']['manifest'],
      $recorded['files']['dump'],
    );
    $this->assertSame(ChainGap::REASON_GAP_MISSING, $missing['reason']);
  }

  /**
   * The archive checker reports linkage and range failures of the file.
   */
  public function testArchiveCheckRejectsBrokenLinkageAndRange(): void {
    foreach (['one', 'two', 'three'] as $operation) {
      $this->chain->logKeyed('audit_chain', $operation);
    }
    $rows = $this->rows();
    $fork = (string) $rows[0]->row_hash;
    $live = (string) $rows[1]->row_hash;
    $brokenPrev = str_repeat('ab', 32);
    $middle = str_repeat('cd', 32);
    $head = str_repeat('ef', 32);

    $linkage = $this->archiveFiles('linkage', $this->ndjson([
      ['id' => 2, 'prev_hash' => $brokenPrev, 'row_hash' => $middle],
      ['id' => 3, 'prev_hash' => $middle, 'row_hash' => $head],
    ]));
    $linkageInput = $this->gapInput(
      'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
      (int) $rows[0]->id,
      $fork,
      $live,
      $linkage,
      2,
      3,
      2,
      $head,
    );
    $linkageRecord = $this->gaps->record($linkageInput, $this->gaps->prepare($linkageInput)['snapshot_digest']);
    $linkageCheck = $this->gaps->checkArchive($linkageRecord['id'], $linkage['archive'], $linkage['manifest'], $linkage['dump']);
    $this->assertFalse($linkageCheck['ok']);
    $this->assertSame(ChainGap::REASON_LINKAGE_BROKEN, $linkageCheck['reason']);

    $range = $this->archiveFiles('range', $this->ndjson([
      ['id' => 2, 'prev_hash' => $fork, 'row_hash' => $middle],
    ]));
    $rangeInput = $this->gapInput(
      'bbbbbbbb-cccc-4ddd-8eee-ffffffffffff',
      (int) $rows[0]->id,
      $fork,
      $live,
      $range,
      2,
      3,
      2,
      $middle,
    );
    $rangeRecord = $this->gaps->record($rangeInput, $this->gaps->prepare($rangeInput)['snapshot_digest']);
    $rangeCheck = $this->gaps->checkArchive($rangeRecord['id'], $range['archive'], $range['manifest'], $range['dump']);
    $this->assertFalse($rangeCheck['ok']);
    $this->assertSame(ChainGap::REASON_RANGE_MISMATCH, $rangeCheck['reason']);
  }

  /**
   * An unreadable gap fails export before any file is written.
   */
  public function testUnreadableGapFailsExportClosed(): void {
    $recorded = $this->recordCleanGap();
    $this->container->get('database')->update('audit_chain_log')
      ->fields(['metadata' => 'not-json'])
      ->condition('id', $recorded['id'])
      ->execute();

    $destination = $this->siteDirectory . '/unreadable-gap.ndjson';
    $exporter = $this->container->get('audit_chain.evidence_exporter');
    $run = $exporter->exportTo('file://' . $destination);
    $this->assertFalse($run['ok']);
    $this->assertSame(EvidenceExporter::REASON_GAP_UNREADABLE, $run['reason']);
    $this->assertSame(0, $run['delivered']);
    $this->assertFileDoesNotExist($destination);

    $dashboard = $this->renderDashboard();
    $this->assertStringContainsString('could not be read', $dashboard);
    $this->assertStringContainsString('at row ' . $recorded['id'], $dashboard);

    try {
      $this->gaps->record($recorded['input'], $recorded['digest']);
      $this->fail('An unreadable gap must not be recorded again.');
    }
    catch (\RuntimeException $exception) {
      $this->assertSame('A recorded gap could not be read.', $exception->getMessage());
    }
    $this->assertSame(1, $this->gapCount());
  }

  /**
   * An archive that begins with the surviving row is not a lost branch.
   */
  public function testArchiveThatRepeatsLiveRowIsNotLostBranch(): void {
    foreach (['one', 'two', 'three'] as $operation) {
      $this->chain->logKeyed('audit_chain', $operation);
    }
    $rows = $this->rows();
    $live = (string) $rows[1]->row_hash;
    $head = str_repeat('ef', 32);
    $files = $this->archiveFiles('repeats-live', $this->ndjson([
      ['id' => 10, 'prev_hash' => (string) $rows[0]->row_hash, 'row_hash' => $live],
      ['id' => 11, 'prev_hash' => $live, 'row_hash' => $head],
    ]));
    $input = $this->gapInput(
      'cccccccc-dddd-4eee-8fff-000000000000',
      (int) $rows[0]->id,
      (string) $rows[0]->row_hash,
      $live,
      $files,
      10,
      11,
      2,
      $head,
    );
    $recorded = $this->gaps->record($input, $this->gaps->prepare($input)['snapshot_digest']);
    $check = $this->gaps->checkArchive($recorded['id'], $files['archive'], $files['manifest'], $files['dump']);
    $this->assertFalse($check['ok']);
    $this->assertSame(ChainGap::REASON_LINKAGE_BROKEN, $check['reason']);
  }

  /**
   * A same-named operation on another channel is not a recorded gap.
   */
  public function testForeignChannelIsNotGap(): void {
    $recorded = $this->recordCleanGap();
    $this->container->get('database')->update('audit_chain_log')
      ->fields(['channel' => 'personnel'])
      ->condition('id', $recorded['id'])
      ->execute();

    $check = $this->gaps->checkArchive(
      $recorded['id'],
      $recorded['files']['archive'],
      $recorded['files']['manifest'],
      $recorded['files']['dump'],
    );
    $this->assertFalse($check['ok']);
    $this->assertSame(ChainGap::REASON_GAP_MISSING, $check['reason']);

    $destination = $this->siteDirectory . '/foreign-channel.ndjson';
    $run = $this->container->get('audit_chain.evidence_exporter')->exportTo('file://' . $destination);
    $this->assertTrue($run['ok']);
    $this->assertNotSame(EvidenceExporter::REASON_GAP_UNREADABLE, $run['reason']);
    $exported = $this->exportedRows('foreign-channel.ndjson');
    $matched = FALSE;
    foreach ($exported as $row) {
      $this->assertArrayNotHasKey('gap', $row);
      if ((int) $row['id'] === $recorded['id']) {
        $matched = TRUE;
        $this->assertSame('personnel', $row['channel']);
        $this->assertSame(ChainGap::OPERATION, $row['operation']);
      }
    }
    $this->assertTrue($matched);
  }

  /**
   * A gap after recovery does not open a second segment.
   */
  public function testGapAfterRecoveryDoesNotOpenSecondSegment(): void {
    new Settings(['audit_chain_instance_id' => 'synthetic-instance-a'] + Settings::getAll());
    $this->makeFork();
    $prepared = $this->recovery->prepare();
    $this->recovery->activate(self::SEGMENT, $prepared['snapshot_digest'], [
      'incident' => 'synthetic-incident',
      'reason' => 'Preserve both authentic branches and their failed verdict.',
      'approved_by' => 'test operator',
      'backup_digest' => str_repeat('a', 64),
    ]);
    $this->assertTrue($this->recovery->verify(self::SEGMENT)['segment_ok']);
    $this->assertFalse($this->chain->verify()['ok']);

    $rows = $this->rows();
    $fork = (string) $rows[0]->row_hash;
    $orphan = (string) $rows[1]->row_hash;
    $surviving = (string) $rows[2]->row_hash;
    $first = str_repeat('ab', 32);
    $head = str_repeat('cd', 32);
    $files = $this->archiveFiles('after-recovery', $this->ndjson([
      ['id' => 10, 'prev_hash' => $fork, 'row_hash' => $first],
      ['id' => 11, 'prev_hash' => $first, 'row_hash' => $head],
    ]));
    $orphanInput = $this->gapInput(
      '123e4567-e89b-42d3-a456-426614174000',
      (int) $rows[0]->id,
      $fork,
      $orphan,
      $files,
      10,
      11,
      2,
      $head,
    );
    try {
      $this->gaps->prepare($orphanInput);
      $this->fail('The orphaned sibling is not the surviving row.');
    }
    catch (\RuntimeException $exception) {
      $this->assertSame('The first live row after the fork does not match.', $exception->getMessage());
    }
    try {
      $this->gaps->record($orphanInput, $this->statementDigest($orphanInput));
      $this->fail('Recording must refuse the orphaned sibling.');
    }
    catch (\RuntimeException $exception) {
      $this->assertSame('The first live row after the fork does not match.', $exception->getMessage());
    }
    $orphanFork = $this->gapInput(
      '123e4567-e89b-42d3-a456-426614174001',
      (int) $rows[1]->id,
      $orphan,
      $surviving,
      $files,
      10,
      11,
      2,
      $head,
    );
    try {
      $this->gaps->prepare($orphanFork);
      $this->fail('The orphaned sibling is not a fork on the surviving chain.');
    }
    catch (\RuntimeException $exception) {
      $this->assertSame('The fork row is not on the surviving chain.', $exception->getMessage());
    }
    $this->assertSame(0, $this->gapCount());

    $input = $this->gapInput(
      '123e4567-e89b-42d3-a456-426614174000',
      (int) $rows[0]->id,
      $fork,
      $surviving,
      $files,
      10,
      11,
      2,
      $head,
    );
    $recorded = $this->gaps->record($input, $this->gaps->prepare($input)['snapshot_digest']);
    $this->assertTrue($recorded['created']);
    $this->assertSame(1, $this->gapCount());
    $this->assertSame(1, $this->recoveryCount());
    $this->assertFalse($this->chain->verify()['ok']);
    $this->assertTrue($this->recovery->verify(self::SEGMENT)['segment_ok']);

    $export = $this->container->get('audit_chain.evidence_exporter')
      ->exportTo('file://' . $this->siteDirectory . '/recovery-blocked.ndjson');
    $this->assertFalse($export['ok']);
    $this->assertSame(EvidenceExporter::REASON_VERIFICATION_FAILING, $export['reason']);
    $this->assertFileDoesNotExist($this->siteDirectory . '/recovery-blocked.ndjson');
  }

  /**
   * A chain that does not verify cannot record a gap.
   */
  public function testBrokenChainRefusesGap(): void {
    $this->makeFork();
    $rows = $this->rows();
    $files = $this->archiveFiles('refused', $this->ndjson([
      ['id' => 10, 'prev_hash' => (string) $rows[0]->row_hash, 'row_hash' => str_repeat('ab', 32)],
    ]));
    $input = $this->gapInput(
      self::GAP_ID,
      (int) $rows[0]->id,
      (string) $rows[0]->row_hash,
      (string) $rows[1]->row_hash,
      $files,
      10,
      10,
      1,
      str_repeat('ab', 32),
    );
    try {
      $this->gaps->prepare($input);
      $this->fail('Prepare must refuse a chain that does not verify.');
    }
    catch (\RuntimeException $exception) {
      $this->assertSame('The chain does not verify.', $exception->getMessage());
    }
    try {
      $this->gaps->record($input, $this->statementDigest($input));
      $this->fail('Record must refuse a chain that does not verify.');
    }
    catch (\RuntimeException $exception) {
      $this->assertSame('The chain does not verify.', $exception->getMessage());
    }
    $this->assertSame(0, $this->gapCount());
    $this->assertCount(3, $this->rows());
  }

  /**
   * Writes three keyed rows and one gap whose lost ids overlap the live rows.
   *
   * @return array{id: int, input: array<string, int|string>, digest: string, files: array<string, string>, archive_head: string}
   *   The recorded gap and the files it names.
   */
  private function recordCleanGap(): array {
    foreach (['one', 'two', 'three'] as $operation) {
      $this->chain->logKeyed('audit_chain', $operation);
    }
    $rows = $this->rows();
    $archiveHead = str_repeat('cd', 32);
    $files = $this->archiveFiles('clean', $this->ndjson([
      [
        'id' => 2,
        'prev_hash' => (string) $rows[0]->row_hash,
        'row_hash' => str_repeat('ab', 32),
        'note' => 'kept',
      ],
      [
        'id' => 3,
        'prev_hash' => str_repeat('ab', 32),
        'row_hash' => $archiveHead,
      ],
    ]));
    $input = $this->gapInput(
      self::GAP_ID,
      (int) $rows[0]->id,
      (string) $rows[0]->row_hash,
      (string) $rows[1]->row_hash,
      $files,
      2,
      3,
      2,
      $archiveHead,
    );
    $prepared = $this->gaps->prepare($input);
    $this->assertSame(0, $this->gapCount());
    $recorded = $this->gaps->record($input, $prepared['snapshot_digest']);
    $this->assertTrue($recorded['created']);
    return [
      'id' => $recorded['id'],
      'input' => $input,
      'digest' => $prepared['snapshot_digest'],
      'files' => $files,
      'archive_head' => $archiveHead,
    ];
  }

  /**
   * Builds a canonical gap statement in digest order.
   *
   * @param string $gapId
   *   Operator gap UUID.
   * @param int $forkId
   *   Live fork row id.
   * @param string $forkHash
   *   Live fork row_hash.
   * @param string $firstLive
   *   The row_hash of the first live row after the fork.
   * @param array<string, string> $files
   *   Archive paths and digests from archiveFiles().
   * @param int $from
   *   First lost id.
   * @param int $through
   *   Last lost id.
   * @param int $count
   *   Lost row count.
   * @param string $lostHead
   *   Lost branch head row_hash.
   *
   * @return array<string, int|string>
   *   Canonical input.
   */
  private function gapInput(string $gapId, int $forkId, string $forkHash, string $firstLive, array $files, int $from, int $through, int $count, string $lostHead): array {
    return [
      'gap_id' => $gapId,
      'fork_id' => $forkId,
      'fork_row_hash' => $forkHash,
      'lost_from_id' => $from,
      'lost_through_id' => $through,
      'lost_count' => $count,
      'lost_from_timestamp' => 100,
      'lost_through_timestamp' => 200,
      'lost_head_row_hash' => $lostHead,
      'first_live_row_hash' => $firstLive,
      'manifest_digest' => $files['manifest_digest'],
      'rows_digest' => $files['rows_digest'],
      'dump_digest' => $files['dump_digest'],
    ];
  }

  /**
   * Digests a statement the same way the gap contract does.
   *
   * Used when prepare() refuses, so the write path can still be attempted.
   *
   * @param array<string, int|string> $gap
   *   Canonical input in digest order.
   *
   * @return string
   *   Lowercase SHA-256 digest.
   */
  private function statementDigest(array $gap): string {
    $encoded = json_encode($gap, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    $this->assertIsString($encoded);
    return hash('sha256', "audit_chain.gap.v1\n" . $encoded);
  }

  /**
   * Writes an archive, a manifest, and a dump.
   *
   * @param string $name
   *   File prefix.
   * @param string $ndjson
   *   Archived branch bytes.
   *
   * @return array<string, string>
   *   Paths and the three digests.
   */
  private function archiveFiles(string $name, string $ndjson): array {
    $archive = $this->archiveDirectory . '/' . $name . '.ndjson';
    $manifest = $this->archiveDirectory . '/' . $name . '.manifest';
    $dump = $this->archiveDirectory . '/' . $name . '.dump';
    file_put_contents($archive, $ndjson);
    file_put_contents($manifest, 'manifest-' . $name);
    file_put_contents($dump, 'dump-' . $name);
    return [
      'archive' => $archive,
      'manifest' => $manifest,
      'dump' => $dump,
      'rows_digest' => $this->fileDigest($archive),
      'manifest_digest' => $this->fileDigest($manifest),
      'dump_digest' => $this->fileDigest($dump),
    ];
  }

  /**
   * Encodes archive rows without sorting them.
   *
   * @param list<array<string, int|string>> $rows
   *   Rows in the order the checker must see.
   *
   * @return string
   *   NDJSON with a trailing newline.
   */
  private function ndjson(array $rows): string {
    $lines = [];
    foreach ($rows as $row) {
      $lines[] = json_encode($row, JSON_THROW_ON_ERROR);
    }
    return implode("\n", $lines) . "\n";
  }

  /**
   * SHA-256 of a file the test just wrote.
   */
  private function fileDigest(string $path): string {
    $digest = hash_file('sha256', $path);
    $this->assertNotFalse($digest);
    return $digest;
  }

  /**
   * Builds a fork whose two branches still have authentic HMACs.
   */
  private function makeFork(): void {
    foreach (['root', 'left', 'right'] as $operation) {
      $this->chain->logKeyed('test', $operation);
    }
    $rows = $this->rows();
    $right = (array) $rows[2];
    $right['prev_hash'] = $rows[0]->row_hash;
    $canonical = new \ReflectionMethod(AuditChainLogger::class, 'canonicalFromRecord');
    $right['row_hash'] = hash_hmac(
      'sha256',
      $right['prev_hash'] . '|' . $canonical->invoke($this->chain, $right),
      'synthetic-recovery-secret',
    );
    $this->container->get('database')->update('audit_chain_log')
      ->fields(['prev_hash' => $right['prev_hash'], 'row_hash' => $right['row_hash']])
      ->condition('id', 3)
      ->execute();
  }

  /**
   * Renders the reports dashboard.
   */
  private function renderDashboard(): string {
    $controller = AuditChainDashboardController::create($this->container);
    $build = $controller->dashboard(Request::create('/admin/reports/audit-chain'));
    return (string) $this->container->get('renderer')->renderRoot($build);
  }

  /**
   * Reads exported NDJSON rows, skipping batch header lines.
   *
   * @return list<array<string, mixed>>
   *   Decoded row objects.
   */
  private function exportedRows(string $name): array {
    $path = $this->siteDirectory . '/' . $name;
    $this->assertFileExists($path);
    $rows = [];
    foreach (array_filter(explode("\n", (string) file_get_contents($path))) as $line) {
      $decoded = json_decode($line, TRUE);
      if (is_array($decoded) && isset($decoded['id'])) {
        $rows[] = $decoded;
      }
    }
    return $rows;
  }

  /**
   * Counts chain_gap_recorded rows.
   */
  private function gapCount(): int {
    return (int) $this->container->get('database')->select('audit_chain_log', 'l')
      ->condition('operation', ChainGap::OPERATION)
      ->countQuery()
      ->execute()
      ->fetchField();
  }

  /**
   * Counts recovery segments.
   */
  private function recoveryCount(): int {
    return (int) $this->container->get('database')->select('audit_chain_recovery', 'r')
      ->countQuery()
      ->execute()
      ->fetchField();
  }

  /**
   * Returns stored rows in chain order.
   *
   * @return list<object>
   *   Chain rows.
   */
  private function rows(): array {
    return $this->container->get('database')->select('audit_chain_log', 'l')
      ->fields('l')
      ->orderBy('id')
      ->execute()
      ->fetchAll();
  }

}
