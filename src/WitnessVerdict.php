<?php

declare(strict_types=1);

namespace Drupal\audit_chain;

/**
 * Fail-closed result of verifying a witness receipt.
 */
final class WitnessVerdict {

  public function __construct(
    public readonly bool $valid,
    public readonly string $reason,
  ) {}

}
