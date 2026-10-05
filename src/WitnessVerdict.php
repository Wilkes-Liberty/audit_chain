<?php

declare(strict_types=1);

namespace Drupal\audit_chain;

/**
 * Fail-closed result of verifying a witness receipt.
 */
final class WitnessVerdict {

  /**
   * Stores one verification result.
   *
   * @param bool $valid
   *   TRUE only after the required proof and finality checks.
   * @param string $reason
   *   Stable machine reason. Not a combined confirmation count.
   * @param array<string, int|string|bool> $evidence
   *   Proof details copied from the witness read. Empty for older callers.
   */
  public function __construct(
    public readonly bool $valid,
    public readonly string $reason,
    public readonly array $evidence = [],
  ) {}

}
