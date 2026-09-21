<?php

declare(strict_types=1);

namespace Drupal\audit_chain;

/**
 * Opaque receipt returned by a witness backend.
 */
final class WitnessReceipt {

  public const STATUS_SUBMITTED = 'submitted';
  public const STATUS_PENDING = 'pending';
  public const STATUS_CONFIRMED = 'confirmed';

  /**
   * Valid persisted receipt states.
   */
  private const STATUSES = [
    self::STATUS_SUBMITTED,
    self::STATUS_PENDING,
    self::STATUS_CONFIRMED,
  ];

  public function __construct(
    public readonly string $id,
    public readonly string $backendId,
    public readonly string $status,
    public readonly string $opaqueToken,
  ) {
    if ($id === '' || strlen($id) > 128) {
      throw new \InvalidArgumentException('A bounded witness receipt id is required.');
    }
    if ($backendId === '' || strlen($backendId) > 64) {
      throw new \InvalidArgumentException('A bounded witness backend id is required.');
    }
    if (!in_array($status, self::STATUSES, TRUE)) {
      throw new \InvalidArgumentException('Unknown witness receipt status.');
    }
  }

}
