<?php

declare(strict_types=1);

namespace Drupal\audit_chain;

use Drupal\Component\Uuid\UuidInterface;

/**
 * Fail-closed placeholder used until a live backend is configured.
 */
final class NullWitnessBackend implements IdentifiedWitnessBackendInterface {

  public function __construct(
    private readonly UuidInterface $uuid,
  ) {}

  /**
   * {@inheritdoc}
   */
  public function id(): string {
    return 'null';
  }

  /**
   * {@inheritdoc}
   */
  public function submit(string $digestHex, array $context): WitnessReceipt {
    return new WitnessReceipt(
      $this->uuid->generate(),
      $this->id(),
      WitnessReceipt::STATUS_PENDING,
      '',
    );
  }

  /**
   * {@inheritdoc}
   */
  public function upgrade(WitnessReceipt $pending): WitnessReceipt {
    return $pending;
  }

  /**
   * {@inheritdoc}
   */
  public function verify(WitnessReceipt $receipt, string $digestHex): WitnessVerdict {
    return new WitnessVerdict(FALSE, 'backend_not_configured');
  }

}
