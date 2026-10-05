<?php

declare(strict_types=1);

namespace Drupal\audit_chain\Witness;

/**
 * Detached OpenTimestamps proof codec.
 *
 * The byte layout follows the detached proof and timestamp tree used by
 * OpenTimestamps: magic, major version, SHA-256 file op, 32-byte digest, then
 * the timestamp. Unknown operations fail closed. Litecoin and unknown
 * attestations are retained and never treated as Bitcoin confirmation.
 */
final class OtsProof {

  public const MAGIC = "\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";

  private const PENDING_TAG = "\x83\xdf\xe3\x0d\x2e\xf9\x0c\x8e";

  private const BITCOIN_TAG = "\x05\x88\x96\x0d\x73\xd7\x19\x01";

  private const LITECOIN_TAG = "\x06\x86\x9a\x0d\x73\xd7\x1b\x45";

  private const MAX_PROOF = 65536;

  private const MAX_PAYLOAD = 8192;

  private const MAX_URI = 1000;

  private const MAX_DEPTH = 32;

  private const URI_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._/:';

  /**
   * Initial message this timestamp commits to.
   */
  private string $message;

  /**
   * Attestations at this node.
   *
   * @var list<array{kind: string, tag: string, payload: string, uri: ?string, height: ?int}>
   */
  private array $attestations = [];

  /**
   * Child operations.
   *
   * @var list<array{tag: string, argument: string, proof: self}>
   */
  private array $edges = [];

  public function __construct(string $message) {
    $this->message = $message;
  }

  /**
   * Returns the message at this node.
   */
  public function message(): string {
    return $this->message;
  }

  /**
   * Returns attestations at this node.
   *
   * @return list<array{kind: string, tag: string, payload: string, uri: ?string, height: ?int}>
   *   Attestations stored on this node.
   */
  public function attestations(): array {
    return $this->attestations;
  }

  /**
   * Wraps a calendar timestamp as a detached SHA-256 proof.
   */
  public static function detachedFromCalendar(string $digest, string $calendarBytes): string {
    $proof = self::decodeTimestamp($calendarBytes, $digest);
    return self::encodeDetached($digest, $proof);
  }

  /**
   * Encodes a detached proof. The proof message must be the file digest.
   */
  public static function encodeDetached(string $digest, self $proof): string {
    if (strlen($digest) !== 32 || !hash_equals($digest, $proof->message)) {
      throw new \RuntimeException('ots_malformed');
    }
    $bytes = self::MAGIC . "\x01\x08" . $digest . $proof->serialize();
    if (strlen($bytes) > self::MAX_PROOF) {
      throw new \RuntimeException('ots_malformed');
    }
    return $bytes;
  }

  /**
   * Decodes a detached proof and returns the embedded digest.
   *
   * @return array{digest: string, proof: self}
   *   The 32-byte file digest and its timestamp tree.
   */
  public static function decodeDetached(string $bytes): array {
    if (strlen($bytes) > self::MAX_PROOF || strlen($bytes) < strlen(self::MAGIC) + 35) {
      throw new \RuntimeException('ots_malformed');
    }
    $cursor = ['bytes' => $bytes, 'at' => 0];
    $magic = self::read($cursor, strlen(self::MAGIC));
    if (!hash_equals(self::MAGIC, $magic)) {
      throw new \RuntimeException('ots_malformed');
    }
    if (self::read($cursor, 1) !== "\x01" || self::read($cursor, 1) !== "\x08") {
      throw new \RuntimeException('ots_malformed');
    }
    $digest = self::read($cursor, 32);
    $proof = self::readStamp($cursor, $digest, self::MAX_DEPTH);
    if (self::remaining($cursor) !== 0) {
      throw new \RuntimeException('ots_malformed');
    }
    return ['digest' => $digest, 'proof' => $proof];
  }

  /**
   * Decodes a calendar timestamp against the submitted digest.
   */
  public static function decodeTimestamp(string $bytes, string $message): self {
    if ($bytes === '' || strlen($bytes) > 10000 || strlen($message) !== 32) {
      throw new \RuntimeException('ots_malformed');
    }
    $cursor = ['bytes' => $bytes, 'at' => 0];
    $proof = self::readStamp($cursor, $message, self::MAX_DEPTH);
    if (self::remaining($cursor) !== 0) {
      throw new \RuntimeException('ots_malformed');
    }
    return $proof;
  }

  /**
   * Whether a calendar response can be completed later or checked now.
   */
  public function hasCompletionRoute(): bool {
    if ($this->pendingNodes(1) !== [] || $this->bitcoinCandidates() !== []) {
      return TRUE;
    }
    return FALSE;
  }

  /**
   * Stamps that still carry a pending calendar attestation.
   *
   * @param int $limit
   *   Maximum number of pending nodes to return.
   *
   * @return list<self>
   *   Pending nodes, oldest in tree order, capped at the limit.
   */
  public function pendingNodes(int $limit = 8): array {
    $found = [];
    $this->collectPending($found, $limit);
    return $found;
  }

  /**
   * Bitcoin attestations and the message each one commits to.
   *
   * @return list<array{height: int, message: string}>
   *   Block height and the message evaluated at that attestation.
   */
  public function bitcoinCandidates(): array {
    $found = [];
    $this->collectBitcoin($found);
    return $found;
  }

  /**
   * Adds attestations and operation edges. Pending attestations stay.
   */
  public function merge(self $other): void {
    if (!hash_equals($this->message, $other->message)) {
      throw new \RuntimeException('ots_message_mismatch');
    }
    foreach ($other->attestations as $attestation) {
      if (!$this->hasAttestation($attestation)) {
        $this->attestations[] = $attestation;
      }
    }
    foreach ($other->edges as $edge) {
      $matched = NULL;
      foreach ($this->edges as $ours) {
        if ($ours['tag'] === $edge['tag'] && hash_equals($ours['argument'], $edge['argument'])) {
          $matched = $ours['proof'];
          break;
        }
      }
      if ($matched === NULL) {
        $this->edges[] = $edge;
      }
      else {
        $matched->merge($edge['proof']);
      }
    }
  }

  /**
   * Serializes this timestamp tree.
   */
  public function serialize(): string {
    if ($this->attestations === [] && $this->edges === []) {
      throw new \RuntimeException('ots_malformed');
    }
    $attestations = $this->attestations;
    usort($attestations, static function (array $left, array $right): int {
      return $left['tag'] . "\x00" . ($left['uri'] ?? '') . sprintf('%020d', $left['height'] ?? 0)
        <=> $right['tag'] . "\x00" . ($right['uri'] ?? '') . sprintf('%020d', $right['height'] ?? 0);
    });
    $edges = $this->edges;
    usort($edges, static function (array $left, array $right): int {
      return $left['tag'] . $left['argument'] <=> $right['tag'] . $right['argument'];
    });
    $out = '';
    $count = count($attestations);
    if ($count > 1) {
      for ($i = 0; $i < $count - 1; $i++) {
        $out .= "\xff\x00" . self::serializeAttestation($attestations[$i]);
      }
    }
    if ($edges === []) {
      $out .= "\x00" . self::serializeAttestation($attestations[$count - 1]);
      return $out;
    }
    if ($count > 0) {
      $out .= "\xff\x00" . self::serializeAttestation($attestations[$count - 1]);
    }
    $last = count($edges) - 1;
    foreach ($edges as $index => $edge) {
      if ($index !== $last) {
        $out .= "\xff";
      }
      $out .= self::serializeOp($edge) . $edge['proof']->serialize();
    }
    return $out;
  }

  /**
   * Collects pending calendar nodes up to a limit.
   *
   * @param list<self> $found
   *   Nodes already collected. Appended in place.
   * @param int $limit
   *   Maximum number of nodes to keep.
   */
  private function collectPending(array &$found, int $limit): void {
    if (count($found) >= $limit) {
      return;
    }
    foreach ($this->attestations as $attestation) {
      if ($attestation['kind'] === 'pending') {
        $found[] = $this;
        break;
      }
    }
    foreach ($this->edges as $edge) {
      $edge['proof']->collectPending($found, $limit);
      if (count($found) >= $limit) {
        return;
      }
    }
  }

  /**
   * Collects Bitcoin attestations from this node and its children.
   *
   * @param list<array{height: int, message: string}> $found
   *   Candidates already collected. Appended in place.
   */
  private function collectBitcoin(array &$found): void {
    foreach ($this->attestations as $attestation) {
      if ($attestation['kind'] === 'bitcoin' && $attestation['height'] !== NULL) {
        $found[] = [
          'height' => $attestation['height'],
          'message' => $this->message,
        ];
      }
    }
    foreach ($this->edges as $edge) {
      $edge['proof']->collectBitcoin($found);
    }
  }

  /**
   * Whether this node already stores an identical attestation.
   *
   * @param array{kind: string, tag: string, payload: string, uri: ?string, height: ?int} $attestation
   *   Attestation to compare.
   *
   * @return bool
   *   TRUE when kind, tag, payload, URI, and height match.
   */
  private function hasAttestation(array $attestation): bool {
    foreach ($this->attestations as $ours) {
      if ($ours['kind'] === $attestation['kind']
        && hash_equals($ours['tag'], $attestation['tag'])
        && hash_equals($ours['payload'], $attestation['payload'])
        && $ours['uri'] === $attestation['uri']
        && $ours['height'] === $attestation['height']) {
        return TRUE;
      }
    }
    return FALSE;
  }

  /**
   * Reads one timestamp node and its operation tree.
   *
   * @param array{bytes: string, at: int} $cursor
   *   Remaining bytes and the read offset.
   * @param string $message
   *   Message this node commits to.
   * @param int $depth
   *   Remaining recursion budget. Zero fails closed.
   *
   * @return self
   *   The decoded timestamp node.
   */
  private static function readStamp(array &$cursor, string $message, int $depth): self {
    if ($depth <= 0) {
      throw new \RuntimeException('ots_malformed');
    }
    $proof = new self($message);
    $tag = self::read($cursor, 1);
    while ($tag === "\xff") {
      self::readBranch($proof, $cursor, $message, $depth, self::read($cursor, 1));
      $tag = self::read($cursor, 1);
    }
    self::readBranch($proof, $cursor, $message, $depth, $tag);
    if ($proof->attestations === [] && $proof->edges === []) {
      throw new \RuntimeException('ots_malformed');
    }
    return $proof;
  }

  /**
   * Reads one attestation or one operation edge onto a node.
   *
   * @param self $proof
   *   Node that receives the attestation or edge.
   * @param array{bytes: string, at: int} $cursor
   *   Remaining bytes and the read offset.
   * @param string $message
   *   Message before this operation is applied.
   * @param int $depth
   *   Remaining recursion budget.
   * @param string $tag
   *   One-byte attestation or operation tag.
   */
  private static function readBranch(self $proof, array &$cursor, string $message, int $depth, string $tag): void {
    if ($tag === "\x00") {
      $proof->attestations[] = self::readAttestation($cursor);
      return;
    }
    if ($tag !== "\x08" && $tag !== "\xf0" && $tag !== "\xf1") {
      throw new \RuntimeException('ots_malformed');
    }
    $argument = '';
    if ($tag === "\xf0" || $tag === "\xf1") {
      $argument = self::readVarbytes($cursor, 4096, 1);
    }
    $childMessage = self::applyOp($tag, $argument, $message);
    $proof->edges[] = [
      'tag' => $tag,
      'argument' => $argument,
      'proof' => self::readStamp($cursor, $childMessage, $depth - 1),
    ];
  }

  /**
   * Reads one attestation payload.
   *
   * @param array{bytes: string, at: int} $cursor
   *   Remaining bytes and the read offset.
   *
   * @return array{kind: string, tag: string, payload: string, uri: ?string, height: ?int}
   *   A pending, Bitcoin, Litecoin, or unknown attestation.
   */
  private static function readAttestation(array &$cursor): array {
    $tag = self::read($cursor, 8);
    $payload = self::readVarbytes($cursor, self::MAX_PAYLOAD, 0);
    $payloadCursor = ['bytes' => $payload, 'at' => 0];
    if ($tag === self::PENDING_TAG) {
      $uri = self::readVarbytes($payloadCursor, self::MAX_URI, 1);
      self::assertUri($uri);
      if (self::remaining($payloadCursor) !== 0) {
        throw new \RuntimeException('ots_malformed');
      }
      return [
        'kind' => 'pending',
        'tag' => $tag,
        'payload' => $payload,
        'uri' => $uri,
        'height' => NULL,
      ];
    }
    if ($tag === self::BITCOIN_TAG || $tag === self::LITECOIN_TAG) {
      $height = self::readVaruint($payloadCursor);
      if (self::remaining($payloadCursor) !== 0 || $height < 0) {
        throw new \RuntimeException('ots_malformed');
      }
      return [
        'kind' => $tag === self::BITCOIN_TAG ? 'bitcoin' : 'litecoin',
        'tag' => $tag,
        'payload' => $payload,
        'uri' => NULL,
        'height' => $height,
      ];
    }
    return [
      'kind' => 'unknown',
      'tag' => $tag,
      'payload' => $payload,
      'uri' => NULL,
      'height' => NULL,
    ];
  }

  /**
   * Applies one allowed operation and returns the child message.
   *
   * @param string $tag
   *   Operation tag. Unknown tags fail closed.
   * @param string $argument
   *   Append or prepend bytes. Empty for SHA-256.
   * @param string $message
   *   Message before the operation.
   *
   * @return string
   *   Message the child timestamp commits to.
   */
  private static function applyOp(string $tag, string $argument, string $message): string {
    if ($tag === "\x08") {
      return hash('sha256', $message, TRUE);
    }
    if ($tag === "\xf0") {
      return $message . $argument;
    }
    if ($tag === "\xf1") {
      return $argument . $message;
    }
    throw new \RuntimeException('ots_malformed');
  }

  /**
   * Serializes one attestation.
   *
   * @param array{kind: string, tag: string, payload: string, uri: ?string, height: ?int} $attestation
   *   Attestation to write.
   *
   * @return string
   *   Tag followed by the payload length and payload.
   */
  private static function serializeAttestation(array $attestation): string {
    return $attestation['tag'] . self::varbytes($attestation['payload']);
  }

  /**
   * Serializes one operation tag and its argument.
   *
   * @param array{tag: string, argument: string, proof: self} $edge
   *   Operation edge. The child proof is written by the caller.
   *
   * @return string
   *   Operation bytes without the child timestamp.
   */
  private static function serializeOp(array $edge): string {
    $bytes = $edge['tag'];
    if ($edge['tag'] === "\xf0" || $edge['tag'] === "\xf1") {
      $bytes .= self::varbytes($edge['argument']);
    }
    return $bytes;
  }

  /**
   * Rejects a calendar URI outside the allowed character set.
   *
   * @param string $uri
   *   Pending-attestation URI.
   */
  private static function assertUri(string $uri): void {
    if ($uri === '' || strlen($uri) > self::MAX_URI) {
      throw new \RuntimeException('ots_malformed');
    }
    $length = strlen($uri);
    for ($i = 0; $i < $length; $i++) {
      if (!str_contains(self::URI_CHARS, $uri[$i])) {
        throw new \RuntimeException('ots_malformed');
      }
    }
  }

  /**
   * Reads a fixed number of bytes and advances the cursor.
   *
   * @param array{bytes: string, at: int} $cursor
   *   Remaining bytes and the read offset.
   * @param int $length
   *   Number of bytes to read.
   *
   * @return string
   *   The bytes that were consumed.
   */
  private static function read(array &$cursor, int $length): string {
    if ($length < 0 || $cursor['at'] + $length > strlen($cursor['bytes'])) {
      throw new \RuntimeException('ots_malformed');
    }
    $out = substr($cursor['bytes'], $cursor['at'], $length);
    $cursor['at'] += $length;
    return $out;
  }

  /**
   * Counts unread bytes.
   *
   * @param array{bytes: string, at: int} $cursor
   *   Remaining bytes and the read offset.
   *
   * @return int
   *   Byte count still unread.
   */
  private static function remaining(array $cursor): int {
    return strlen($cursor['bytes']) - $cursor['at'];
  }

  /**
   * Reads an OpenTimestamps variable-length unsigned integer.
   *
   * @param array{bytes: string, at: int} $cursor
   *   Remaining bytes and the read offset.
   *
   * @return int
   *   Decoded integer. Oversized values fail closed.
   */
  private static function readVaruint(array &$cursor): int {
    $value = 0;
    $shift = 0;
    while (TRUE) {
      if ($shift > 28) {
        throw new \RuntimeException('ots_malformed');
      }
      $byte = ord(self::read($cursor, 1));
      $value |= ($byte & 0x7f) << $shift;
      if (($byte & 0x80) === 0) {
        return $value;
      }
      $shift += 7;
    }
  }

  /**
   * Reads a length-prefixed byte string.
   *
   * @param array{bytes: string, at: int} $cursor
   *   Remaining bytes and the read offset.
   * @param int $max
   *   Maximum accepted length.
   * @param int $min
   *   Minimum accepted length.
   *
   * @return string
   *   The length-prefixed payload.
   */
  private static function readVarbytes(array &$cursor, int $max, int $min): string {
    $length = self::readVaruint($cursor);
    if ($length < $min || $length > $max) {
      throw new \RuntimeException('ots_malformed');
    }
    return self::read($cursor, $length);
  }

  /**
   * Encodes an unsigned integer as an OpenTimestamps varuint.
   *
   * @param int $value
   *   Non-negative integer.
   *
   * @return string
   *   Little-endian base-128 bytes.
   */
  private static function varuint(int $value): string {
    if ($value < 0) {
      throw new \RuntimeException('ots_malformed');
    }
    if ($value === 0) {
      return "\x00";
    }
    $out = '';
    while ($value > 0) {
      $byte = $value & 0x7f;
      $value >>= 7;
      if ($value > 0) {
        $byte |= 0x80;
      }
      $out .= chr($byte);
    }
    return $out;
  }

  /**
   * Encodes a byte string with its varuint length.
   *
   * @param string $bytes
   *   Payload to prefix.
   *
   * @return string
   *   Length followed by the payload.
   */
  private static function varbytes(string $bytes): string {
    return self::varuint(strlen($bytes)) . $bytes;
  }

}
