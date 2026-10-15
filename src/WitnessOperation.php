<?php

declare(strict_types=1);

namespace Drupal\audit_chain;

/**
 * Result of one witness command.
 */
final class WitnessOperation {

  /**
   * Stores one command result.
   *
   * @param int $exitCode
   *   Process exit code.
   * @param list<string> $lines
   *   Lines the command prints.
   * @param string|null $bytes
   *   Portable evidence, or NULL when the command prints lines only.
   */
  public function __construct(
    public readonly int $exitCode,
    public readonly array $lines,
    public readonly ?string $bytes = NULL,
  ) {}

}
