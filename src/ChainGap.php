<?php

declare(strict_types=1);

namespace Drupal\audit_chain;

use Drupal\Component\Uuid\Uuid;
use Drupal\Core\Database\Connection;

/**
 * Records one known gap without rewriting the surviving chain.
 *
 * A second recovery segment stays refused. This appends a single keyed
 * chain_gap_recorded row after the operator reviews a canonical statement.
 * Whole-history verification is unchanged: a chain that still links stays
 * successful, and an existing successor is not replaced.
 */
final class ChainGap {

  public const CHANNEL = 'audit_chain';

  public const OPERATION = 'chain_gap_recorded';

  public const REASON_DIGEST_MISMATCH = 'digest_mismatch';

  public const REASON_LINKAGE_BROKEN = 'linkage_broken';

  public const REASON_RANGE_MISMATCH = 'range_mismatch';

  public const REASON_UNREADABLE = 'unreadable';

  public const REASON_GAP_MISSING = 'gap_missing';

  /**
   * Largest archive, manifest, or dump the checker will read.
   */
  private const MAX_ARCHIVE_BYTES = 33554432;

  /**
   * JSON flags frozen for the gap statement.
   */
  private const JSON_FLAGS = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR;

  /**
   * Canonical field order. The digest covers this order.
   */
  private const FIELDS = [
    'gap_id',
    'fork_id',
    'fork_row_hash',
    'lost_from_id',
    'lost_through_id',
    'lost_count',
    'lost_from_timestamp',
    'lost_through_timestamp',
    'lost_head_row_hash',
    'first_live_row_hash',
    'manifest_digest',
    'rows_digest',
    'dump_digest',
  ];

  public function __construct(
    private readonly Connection $database,
    private readonly AuditChainLogger $chain,
    private readonly RecoverySegments $recovery,
  ) {}

  /**
   * Reviews a gap statement and the live anchor it names.
   *
   * @param array<string, mixed> $input
   *   The operator's statement. Unknown keys are refused.
   *
   * @return array{gap: array<string, int|string>, snapshot_digest: string}
   *   The canonical statement and the digest record() requires.
   */
  public function prepare(array $input): array {
    $statement = $this->statement($input);
    return $this->chain->withChainLock(function () use ($statement): array {
      $this->assertRecordable($statement['gap']);
      return $statement;
    });
  }

  /**
   * Appends the reviewed gap, or returns the existing row on an exact retry.
   *
   * @param array<string, mixed> $input
   *   The same statement passed to prepare().
   * @param string $expectedDigest
   *   Digest returned by prepare().
   *
   * @return array{id: int, gap: array<string, int|string>, snapshot_digest: string, created: bool}
   *   The chain row id and whether this call appended it.
   */
  public function record(array $input, string $expectedDigest): array {
    $statement = $this->statement($input);
    if (!preg_match('/^[a-f0-9]{64}$/D', $expectedDigest)
      || !hash_equals($statement['snapshot_digest'], $expectedDigest)) {
      throw new \InvalidArgumentException('The approved gap statement does not match this digest.');
    }
    return $this->chain->withChainLock(function () use ($statement): array {
      $existing = $this->findByGapId($statement['gap']['gap_id']);
      if ($existing !== NULL) {
        if (!hash_equals($statement['snapshot_digest'], $existing['snapshot_digest'])) {
          throw new \RuntimeException('The gap identifier already belongs to a different statement.');
        }
        return [
          'id' => $existing['id'],
          'gap' => $existing['gap'],
          'snapshot_digest' => $existing['snapshot_digest'],
          'created' => FALSE,
        ];
      }
      $this->assertRecordable($statement['gap']);
      $this->chain->logKeyed(self::CHANNEL, self::OPERATION, $statement['gap']);
      $id = $this->database->select('audit_chain_log', 'l')
        ->fields('l', ['id'])
        ->orderBy('id', 'DESC')
        ->range(0, 1)
        ->execute()
        ->fetchField();
      return [
        'id' => (int) $id,
        'gap' => $statement['gap'],
        'snapshot_digest' => $statement['snapshot_digest'],
        'created' => TRUE,
      ];
    });
  }

  /**
   * Lists recorded gaps for the dashboard.
   *
   * Decrypts only chain_gap_recorded rows. Other metadata is not read.
   *
   * @return list<array{row_id: int, readable: bool, fork_id: int|null, lost_from_id: int|null, lost_through_id: int|null, lost_count: int|null}>
   *   One entry per gap row, in id order.
   */
  public function recorded(): array {
    $listed = [];
    foreach ($this->gapRows() as $row) {
      try {
        $gap = $this->canonicalFromStored((string) ($row->metadata ?? ''), (string) ($row->encryption_profile ?? ''));
        $listed[] = [
          'row_id' => (int) $row->id,
          'readable' => TRUE,
          'fork_id' => $gap['fork_id'],
          'lost_from_id' => $gap['lost_from_id'],
          'lost_through_id' => $gap['lost_through_id'],
          'lost_count' => $gap['lost_count'],
        ];
      }
      catch (\Throwable) {
        $listed[] = [
          'row_id' => (int) $row->id,
          'readable' => FALSE,
          'fork_id' => NULL,
          'lost_from_id' => NULL,
          'lost_through_id' => NULL,
          'lost_count' => NULL,
        ];
      }
    }
    return $listed;
  }

  /**
   * Returns the canonical gap object for one exported row.
   *
   * @param int $rowId
   *   Chain row id.
   *
   * @return array<string, int|string>
   *   Canonical gap fields.
   *
   * @throws \RuntimeException
   *   When the row is not a readable gap. The message is gap_unreadable.
   */
  public function exportFields(int $rowId): array {
    $row = $this->gapRow($rowId);
    if ($row === NULL || !$this->isGapIdentity($row)) {
      throw new \RuntimeException('gap_unreadable');
    }
    try {
      return $this->canonicalFromStored((string) ($row->metadata ?? ''), (string) ($row->encryption_profile ?? ''));
    }
    catch (\Throwable $exception) {
      throw new \RuntimeException('gap_unreadable', 0, $exception);
    }
  }

  /**
   * Checks an archived branch against one recorded gap.
   *
   * Reads the three files and does not write. Timestamps in the statement
   * are not re-proved from the archive.
   *
   * @param int $rowId
   *   Recorded gap row id.
   * @param string $archive
   *   NDJSON file of the lost branch, in id order.
   * @param string $manifest
   *   Manifest file whose raw bytes were digested.
   * @param string $dump
   *   Source dump file whose raw bytes were digested.
   *
   * @return array{ok: bool, reason: string|null}
   *   ok is FALSE with a stable reason when the files do not prove the gap.
   */
  public function checkArchive(int $rowId, string $archive, string $manifest, string $dump): array {
    try {
      $loaded = $this->loadCanonical($rowId);
    }
    catch (\RuntimeException $exception) {
      $reason = $exception->getMessage();
      if ($reason !== self::REASON_GAP_MISSING && $reason !== self::REASON_UNREADABLE) {
        $reason = self::REASON_UNREADABLE;
      }
      return ['ok' => FALSE, 'reason' => $reason];
    }
    try {
      $this->assertLocalFile($archive);
      $this->assertLocalFile($manifest);
      $this->assertLocalFile($dump);
      $rowsDigest = $this->fileDigest($archive);
      $manifestDigest = $this->fileDigest($manifest);
      $dumpDigest = $this->fileDigest($dump);
      if (!hash_equals($loaded['rows_digest'], $rowsDigest)
        || !hash_equals($loaded['manifest_digest'], $manifestDigest)
        || !hash_equals($loaded['dump_digest'], $dumpDigest)) {
        return ['ok' => FALSE, 'reason' => self::REASON_DIGEST_MISMATCH];
      }
      $rows = $this->archivedRows($archive);
    }
    catch (\Throwable) {
      return ['ok' => FALSE, 'reason' => self::REASON_UNREADABLE];
    }
    if ($rows === []
      || count($rows) !== $loaded['lost_count']
      || $rows[0]['id'] !== $loaded['lost_from_id']
      || $rows[array_key_last($rows)]['id'] !== $loaded['lost_through_id']) {
      return ['ok' => FALSE, 'reason' => self::REASON_RANGE_MISMATCH];
    }
    // The surviving row cannot also be the first row of the lost branch.
    if (hash_equals($loaded['first_live_row_hash'], $rows[0]['row_hash'])) {
      return ['ok' => FALSE, 'reason' => self::REASON_LINKAGE_BROKEN];
    }
    $prev = $loaded['fork_row_hash'];
    $lastId = $loaded['fork_id'];
    foreach ($rows as $row) {
      if ($row['id'] <= $lastId || !hash_equals($prev, $row['prev_hash'])) {
        return ['ok' => FALSE, 'reason' => self::REASON_LINKAGE_BROKEN];
      }
      $prev = $row['row_hash'];
      $lastId = $row['id'];
    }
    if (!hash_equals($loaded['lost_head_row_hash'], $prev)) {
      return ['ok' => FALSE, 'reason' => self::REASON_LINKAGE_BROKEN];
    }
    return ['ok' => TRUE, 'reason' => NULL];
  }

  /**
   * Builds the canonical statement and its digest.
   *
   * @param array<string, mixed> $input
   *   Operator statement.
   *
   * @return array{gap: array<string, int|string>, snapshot_digest: string}
   *   Canonical fields in digest order.
   */
  private function statement(array $input): array {
    $gap = $this->normalize($input);
    return [
      'gap' => $gap,
      'snapshot_digest' => hash('sha256', "audit_chain.gap.v1\n" . json_encode($gap, self::JSON_FLAGS)),
    ];
  }

  /**
   * Copies the known fields into digest order.
   *
   * @param array<string, mixed> $input
   *   Operator statement.
   *
   * @return array<string, int|string>
   *   Canonical fields.
   */
  private function normalize(array $input): array {
    $unknown = array_diff(array_keys($input), self::FIELDS);
    if ($unknown !== []) {
      throw new \InvalidArgumentException('The gap statement contains an unknown field.');
    }
    $gap = [];
    foreach (self::FIELDS as $field) {
      if (!array_key_exists($field, $input)) {
        throw new \InvalidArgumentException('The gap statement is missing ' . $field . '.');
      }
      $gap[$field] = $input[$field];
    }
    if (!is_string($gap['gap_id']) || !Uuid::isValid($gap['gap_id'])) {
      throw new \InvalidArgumentException('A gap UUID is required.');
    }
    foreach ([
      'fork_row_hash',
      'lost_head_row_hash',
      'first_live_row_hash',
      'manifest_digest',
      'rows_digest',
      'dump_digest',
    ] as $field) {
      if (!is_string($gap[$field]) || preg_match('/^[a-f0-9]{64}$/D', $gap[$field]) !== 1) {
        throw new \InvalidArgumentException('Gap hashes must be lowercase SHA-256 digests.');
      }
    }
    foreach ([
      'fork_id',
      'lost_from_id',
      'lost_through_id',
      'lost_count',
      'lost_from_timestamp',
      'lost_through_timestamp',
    ] as $field) {
      if (!is_int($gap[$field])) {
        throw new \InvalidArgumentException('Gap ids, counts, and timestamps must be integers.');
      }
    }
    if ($gap['fork_id'] < 1
      || $gap['lost_from_id'] <= $gap['fork_id']
      || $gap['lost_through_id'] < $gap['lost_from_id']
      || $gap['lost_count'] < 1
      || $gap['lost_from_timestamp'] < 0
      || $gap['lost_through_timestamp'] < $gap['lost_from_timestamp']) {
      throw new \InvalidArgumentException('The lost range must follow the fork.');
    }
    return $gap;
  }

  /**
   * Refuses a statement the live chain cannot anchor.
   *
   * @param array<string, int|string> $gap
   *   Canonical statement.
   */
  private function assertRecordable(array $gap): void {
    $status = $this->recovery->currentStatus();
    if ($status !== NULL) {
      $segmentId = $status['segment_id'] ?? NULL;
      if (empty($status['segment_ok']) || !is_string($segmentId) || $segmentId === '') {
        throw new \RuntimeException('The recovery segment does not verify.');
      }
      $this->recovery->assertSurvivingAnchor(
        $segmentId,
        (int) $gap['fork_id'],
        (string) $gap['fork_row_hash'],
        (string) $gap['first_live_row_hash'],
      );
      return;
    }
    $verdict = $this->chain->verify();
    if (empty($verdict['ok'])) {
      throw new \RuntimeException('The chain does not verify.');
    }
    $fork = $this->database->select('audit_chain_log', 'l')
      ->fields('l', ['row_hash'])
      ->condition('id', $gap['fork_id'])
      ->execute()
      ->fetchField();
    if (!is_string($fork) || !hash_equals($gap['fork_row_hash'], $fork)) {
      throw new \RuntimeException('The fork row is not the live row at that id.');
    }
    $live = $this->database->select('audit_chain_log', 'l')
      ->fields('l', ['prev_hash', 'row_hash'])
      ->condition('id', $gap['fork_id'], '>')
      ->orderBy('id')
      ->range(0, 1)
      ->execute()
      ->fetchAssoc();
    $forkHash = (string) $gap['fork_row_hash'];
    $liveHash = (string) $gap['first_live_row_hash'];
    if (!is_array($live)
      || !is_string($live['prev_hash'])
      || !is_string($live['row_hash'])
      || strlen($live['prev_hash']) !== strlen($forkHash)
      || !hash_equals($forkHash, $live['prev_hash'])
      || !hash_equals($liveHash, $live['row_hash'])) {
      throw new \RuntimeException('The first live row after the fork does not match.');
    }
  }

  /**
   * Loads one recorded gap and its canonical statement.
   *
   * @param int $rowId
   *   Chain row id.
   *
   * @return array<string, int|string>
   *   Canonical fields.
   */
  private function loadCanonical(int $rowId): array {
    $row = $this->gapRow($rowId);
    if ($row === NULL || !$this->isGapIdentity($row)) {
      throw new \RuntimeException(self::REASON_GAP_MISSING);
    }
    try {
      return $this->canonicalFromStored((string) ($row->metadata ?? ''), (string) ($row->encryption_profile ?? ''));
    }
    catch (\Throwable $exception) {
      throw new \RuntimeException(self::REASON_UNREADABLE, 0, $exception);
    }
  }

  /**
   * Decodes a stored gap row back into canonical fields.
   *
   * @param string $stored
   *   Stored metadata.
   * @param string $profile
   *   Encryption profile recorded on the row.
   *
   * @return array<string, int|string>
   *   Canonical fields.
   */
  private function canonicalFromStored(string $stored, string $profile): array {
    $decoded = $this->chain->decodeMetadata($stored, $profile);
    return $this->normalize($decoded);
  }

  /**
   * Finds an existing gap row by its operator-supplied id.
   *
   * @param string $gapId
   *   Gap UUID.
   *
   * @return array{id: int, gap: array<string, int|string>, snapshot_digest: string}|null
   *   The existing row, or NULL.
   */
  private function findByGapId(string $gapId): ?array {
    $found = NULL;
    foreach ($this->gapRows() as $row) {
      try {
        $gap = $this->canonicalFromStored((string) ($row->metadata ?? ''), (string) ($row->encryption_profile ?? ''));
      }
      catch (\Throwable $exception) {
        throw new \RuntimeException('A recorded gap could not be read.', 0, $exception);
      }
      if ($gap['gap_id'] !== $gapId) {
        continue;
      }
      if ($found !== NULL) {
        throw new \RuntimeException('The gap identifier already belongs to a different statement.');
      }
      $found = [
        'id' => (int) $row->id,
        'gap' => $gap,
        'snapshot_digest' => hash('sha256', "audit_chain.gap.v1\n" . json_encode($gap, self::JSON_FLAGS)),
      ];
    }
    return $found;
  }

  /**
   * Loads gap rows in id order.
   *
   * @return list<object>
   *   Matching chain rows.
   */
  private function gapRows(): array {
    return $this->database->select('audit_chain_log', 'l')
      ->fields('l', ['id', 'operation', 'metadata', 'encryption_profile'])
      ->condition('channel', self::CHANNEL)
      ->condition('operation', self::OPERATION)
      ->orderBy('id')
      ->execute()
      ->fetchAll();
  }

  /**
   * Loads one chain row.
   *
   * @param int $rowId
   *   Chain row id.
   *
   * @return object|null
   *   The row, or NULL.
   */
  private function gapRow(int $rowId): ?object {
    $row = $this->database->select('audit_chain_log', 'l')
      ->fields('l', ['id', 'channel', 'operation', 'metadata', 'encryption_profile'])
      ->condition('id', $rowId)
      ->execute()
      ->fetch();
    return $row === FALSE ? NULL : $row;
  }

  /**
   * Whether a row is an audit-chain gap record.
   *
   * Channel and operation together are the identity. Another channel may
   * reuse the operation name.
   */
  private function isGapIdentity(object $row): bool {
    return (string) ($row->channel ?? '') === self::CHANNEL
      && (string) ($row->operation ?? '') === self::OPERATION;
  }

  /**
   * Refuses a URL, a missing file, or a file over the read cap.
   *
   * @param string $path
   *   Local filesystem path.
   */
  private function assertLocalFile(string $path): void {
    if (preg_match('#^[a-z][a-z0-9+.-]*://#i', $path) === 1 || !is_file($path)) {
      throw new \RuntimeException(self::REASON_UNREADABLE);
    }
    $size = filesize($path);
    if ($size === FALSE || $size > self::MAX_ARCHIVE_BYTES) {
      throw new \RuntimeException(self::REASON_UNREADABLE);
    }
  }

  /**
   * SHA-256 of a local file's raw bytes.
   *
   * @param string $path
   *   Local filesystem path already accepted by assertLocalFile().
   *
   * @return string
   *   Lowercase digest.
   */
  private function fileDigest(string $path): string {
    $digest = hash_file('sha256', $path);
    if ($digest === FALSE) {
      throw new \RuntimeException(self::REASON_UNREADABLE);
    }
    return $digest;
  }

  /**
   * Parses an archived branch without sorting it.
   *
   * @param string $path
   *   NDJSON file.
   *
   * @return list<array{id: int, prev_hash: string, row_hash: string}>
   *   Rows in file order.
   */
  private function archivedRows(string $path): array {
    $raw = file_get_contents($path);
    if ($raw === FALSE) {
      throw new \RuntimeException(self::REASON_UNREADABLE);
    }
    $lines = preg_split("/\r\n|\n|\r/", $raw);
    if ($lines === FALSE) {
      throw new \RuntimeException(self::REASON_UNREADABLE);
    }
    if ($lines !== [] && $lines[array_key_last($lines)] === '') {
      array_pop($lines);
    }
    $rows = [];
    foreach ($lines as $line) {
      if ($line === '') {
        throw new \RuntimeException(self::REASON_UNREADABLE);
      }
      try {
        $decoded = json_decode($line, TRUE, 32, JSON_THROW_ON_ERROR);
      }
      catch (\JsonException $exception) {
        throw new \RuntimeException(self::REASON_UNREADABLE, 0, $exception);
      }
      if (!is_array($decoded) || !isset($decoded['id'], $decoded['prev_hash'], $decoded['row_hash'])) {
        throw new \RuntimeException(self::REASON_UNREADABLE);
      }
      $id = $decoded['id'];
      $prev = $decoded['prev_hash'];
      $hash = $decoded['row_hash'];
      if (!is_int($id)
        || !is_string($prev) || preg_match('/^[a-f0-9]{64}$/D', $prev) !== 1
        || !is_string($hash) || preg_match('/^[a-f0-9]{64}$/D', $hash) !== 1) {
        throw new \RuntimeException(self::REASON_UNREADABLE);
      }
      $rows[] = [
        'id' => $id,
        'prev_hash' => $prev,
        'row_hash' => $hash,
      ];
    }
    return $rows;
  }

}
