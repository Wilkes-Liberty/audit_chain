<?php

declare(strict_types=1);

namespace Drupal\audit_chain;

/**
 * Sends checkpoint digests to an external witness.
 *
 * Implementations receive a digest and bounded non-personal context only.
 * They must never receive audit rows, metadata, or channel names.
 */
interface WitnessBackendInterface {

  /**
   * Submits a checkpoint digest.
   */
  public function submit(string $digestHex, array $context): WitnessReceipt;

  /**
   * Attempts to advance a pending receipt.
   */
  public function upgrade(WitnessReceipt $pending): WitnessReceipt;

  /**
   * Verifies a receipt against the expected checkpoint digest.
   */
  public function verify(WitnessReceipt $receipt, string $digestHex): WitnessVerdict;

}
