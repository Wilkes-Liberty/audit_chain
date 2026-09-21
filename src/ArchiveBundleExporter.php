<?php

declare(strict_types=1);

namespace Drupal\audit_chain;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Site\Settings;

/**
 * Creates deterministic, data-minimized archive checkpoint bundles.
 */
final class ArchiveBundleExporter {

  public const CONTRACT_VERSION = 1;
  public const CONTRACT = 'audit_chain.archive.v1';

  /**
   * JSON flags frozen for the v1 archival contract.
   */
  private const JSON_FLAGS = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR;

  public function __construct(
    private readonly Connection $database,
    private readonly AuditChainLogger $chain,
    private readonly RecoverySegments $recovery,
    private readonly TimeInterface $time,
  ) {}

  /**
   * Closes, persists, and returns one global export window.
   *
   * @return array
   *   Versioned manifest, minimized rows, Merkle material, and verification
   *   recipe. No row content or signing material is returned.
   */
  public function create(int $fromId = 1, ?int $throughId = NULL): array {
    if ($fromId < 1 || ($throughId !== NULL && $throughId < $fromId)) {
      throw new \InvalidArgumentException('The archive window must use positive ascending row ids.');
    }
    return $this->chain->withChainLock(function () use ($fromId, $throughId): array {
      $verdict = $this->chain->verify();
      $successor = $this->recovery->currentStatus();
      if ((!$verdict['ok'] || $successor !== NULL)
        && ($successor === NULL || empty($successor['segment_ok']))) {
        throw new \RuntimeException('Archive checkpoint refused: the chain or its successor segment does not verify.');
      }
      $resolvedThrough = $throughId ?? $this->latestId();
      if ($resolvedThrough < $fromId) {
        throw new \RuntimeException('The requested archive window is empty.');
      }
      $rows = $this->rows($fromId, $resolvedThrough);
      if ($rows === [] || $rows[0]['id'] !== $fromId
        || $rows[array_key_last($rows)]['id'] !== $resolvedThrough) {
        throw new \RuntimeException('Both archive window boundaries must name stored audit rows.');
      }

      $merkle = $this->merkle($rows);
      $manifest = [
        'contract' => self::CONTRACT,
        'contract_version' => self::CONTRACT_VERSION,
        'instance_id' => $this->instanceId(),
        'window' => [
          'from_id' => $fromId,
          'through_id' => $resolvedThrough,
          'row_count' => count($rows),
        ],
        'hash_algorithm' => 'sha256',
        'merkle_algorithm' => 'audit_chain.merkle.v1',
        'merkle_root' => $merkle['root'],
        'chain_head' => $rows[array_key_last($rows)]['row_hash'],
        'seal' => $this->sealCommitment(),
        'successor' => $this->successorCommitment(),
      ];
      $digest = hash('sha256', "audit_chain.checkpoint.v1\n" . self::encode($manifest));
      $manifest['digest'] = $digest;
      $this->persist($manifest);

      return [
        'manifest' => $manifest,
        'rows' => $rows,
        'merkle' => $merkle,
        'verification' => [
          'row_encoding' => 'UTF-8 JSON with the four row members in emitted order and no insignificant whitespace.',
          'leaf' => 'SHA-256 of "audit_chain.archive.leaf.v1\\n" followed by the encoded row.',
          'node' => 'SHA-256 of "audit_chain.archive.node.v1\\n" followed by the left and right lowercase hex hashes; duplicate an unpaired right leaf.',
          'checkpoint' => 'SHA-256 of "audit_chain.checkpoint.v1\\n" followed by the manifest without its digest member.',
        ],
      ];
    });
  }

  /**
   * Returns the last stored row id.
   */
  private function latestId(): int {
    $id = $this->database->select('audit_chain_log', 'l')
      ->fields('l', ['id'])->orderBy('id', 'DESC')->range(0, 1)
      ->execute()->fetchField();
    return $id === FALSE ? 0 : (int) $id;
  }

  /**
   * Reads only identifiers and stored hash-chain columns.
   */
  private function rows(int $fromId, int $throughId): array {
    $result = $this->database->select('audit_chain_log', 'l')
      ->fields('l', ['id', 'prev_hash', 'row_hash'])
      ->condition('id', $fromId, '>=')
      ->condition('id', $throughId, '<=')
      ->orderBy('id')
      ->execute();
    $rows = [];
    foreach ($result as $record) {
      $rows[] = [
        'contract_version' => EvidenceExporter::CONTRACT_VERSION,
        'id' => (int) $record->id,
        'prev_hash' => $record->prev_hash === NULL ? NULL : (string) $record->prev_hash,
        'row_hash' => $record->row_hash === NULL ? NULL : (string) $record->row_hash,
      ];
    }
    return $rows;
  }

  /**
   * Builds the v1 Merkle root and an inclusion path for every row.
   */
  private function merkle(array $rows): array {
    $leafHashes = [];
    $leaves = [];
    foreach ($rows as $row) {
      $hash = hash('sha256', "audit_chain.archive.leaf.v1\n" . self::encode($row));
      $leafHashes[] = $hash;
      $leaves[] = ['id' => $row['id'], 'hash' => $hash];
    }

    $levels = [$leafHashes];
    while (count($levels[array_key_last($levels)]) > 1) {
      $current = $levels[array_key_last($levels)];
      $next = [];
      for ($index = 0; $index < count($current); $index += 2) {
        $left = $current[$index];
        $right = $current[$index + 1] ?? $left;
        $next[] = hash('sha256', "audit_chain.archive.node.v1\n" . $left . $right);
      }
      $levels[] = $next;
    }

    $proofs = [];
    foreach ($rows as $leafIndex => $row) {
      $path = [];
      $index = $leafIndex;
      for ($level = 0; $level < count($levels) - 1; $level++) {
        $nodes = $levels[$level];
        $isRight = $index % 2 === 1;
        $sibling = $isRight ? $index - 1 : min($index + 1, count($nodes) - 1);
        $path[] = [
          'side' => $isRight ? 'left' : 'right',
          'hash' => $nodes[$sibling],
        ];
        $index = intdiv($index, 2);
      }
      $proofs[] = ['id' => $row['id'], 'path' => $path];
    }

    return [
      'root' => $levels[array_key_last($levels)][0],
      'leaves' => $leaves,
      'proofs' => $proofs,
    ];
  }

  /**
   * Commits to the complete prefix seal without exporting its human context.
   */
  private function sealCommitment(): ?array {
    $seal = $this->chain->getSeal();
    if ($seal === NULL) {
      return NULL;
    }
    $canonicalSeal = [
      'sealed_through_id' => (int) $seal['sealed_through_id'],
      'row_count' => (int) $seal['row_count'],
      'prefix_digest' => (string) $seal['prefix_digest'],
      'seal_mac' => (string) $seal['seal_mac'],
      'timestamp' => (int) $seal['timestamp'],
      'uid' => (int) $seal['uid'],
      'reason' => (string) $seal['reason'],
      'key_id' => (string) $seal['key_id'],
    ];
    return [
      'sealed_through_id' => $canonicalSeal['sealed_through_id'],
      'row_count' => $canonicalSeal['row_count'],
      'prefix_digest' => $canonicalSeal['prefix_digest'],
      'record_digest' => hash('sha256', self::encode($canonicalSeal)),
    ];
  }

  /**
   * Commits to the existing successor record without exporting its context.
   */
  private function successorCommitment(): ?array {
    if (!$this->database->schema()->tableExists('audit_chain_recovery')) {
      return NULL;
    }
    $record = $this->database->select('audit_chain_recovery', 'r')
      ->fields('r', ['segment_id', 'manifest', 'key_id', 'mac'])
      ->range(0, 1)->execute()->fetchAssoc();
    if ($record === FALSE) {
      return NULL;
    }
    $canonicalRecord = [
      'segment_id' => (string) $record['segment_id'],
      'manifest' => (string) $record['manifest'],
      'key_id' => (string) $record['key_id'],
      'mac' => (string) $record['mac'],
    ];
    return [
      'segment_id' => $canonicalRecord['segment_id'],
      'manifest_digest' => hash('sha256', $canonicalRecord['manifest']),
      'record_digest' => hash('sha256', self::encode($canonicalRecord)),
    ];
  }

  /**
   * Persists a stable checkpoint record without adding an audit-chain row.
   */
  private function persist(array $manifest): void {
    $digest = (string) $manifest['digest'];
    $exists = $this->database->select('audit_chain_checkpoint', 'c')
      ->fields('c', ['digest'])->condition('digest', $digest)
      ->execute()->fetchField();
    if ($exists !== FALSE) {
      return;
    }
    $this->database->insert('audit_chain_checkpoint')->fields([
      'digest' => $digest,
      'contract_version' => self::CONTRACT_VERSION,
      'from_id' => $manifest['window']['from_id'],
      'through_id' => $manifest['window']['through_id'],
      'row_count' => $manifest['window']['row_count'],
      'created' => $this->time->getCurrentTime(),
      'manifest' => self::encode($manifest),
    ])->execute();
  }

  /**
   * Requires the same runtime identity as successor segments.
   */
  private function instanceId(): string {
    $identity = Settings::get('audit_chain_instance_id');
    if (!is_string($identity) || trim($identity) === '' || strlen($identity) > 255) {
      throw new \RuntimeException('Configure a unique runtime audit_chain_instance_id before creating an archive checkpoint.');
    }
    return $identity;
  }

  /**
   * Encodes a contract object without lossy fallback.
   */
  private static function encode(mixed $value): string {
    return json_encode($value, self::JSON_FLAGS);
  }

}
