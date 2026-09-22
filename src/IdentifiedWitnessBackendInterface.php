<?php

declare(strict_types=1);

namespace Drupal\audit_chain;

/**
 * Gives a configured witness backend its stable service identifier.
 */
interface IdentifiedWitnessBackendInterface extends WitnessBackendInterface {

  /**
   * Returns the configuration identifier for this backend.
   */
  public function id(): string;

}
