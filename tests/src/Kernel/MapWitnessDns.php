<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain\Kernel;

use Drupal\audit_chain\Witness\WitnessDnsResolverInterface;

/**
 * DNS double keyed by hostname.
 */
final class MapWitnessDns implements WitnessDnsResolverInterface {

  /**
   * Stores the hostname map.
   *
   * @param array<string, list<string>> $map
   *   Hostnames to the addresses a lookup would return.
   */
  public function __construct(
    private array $map,
  ) {}

  /**
   * {@inheritdoc}
   */
  public function resolve(string $host): array {
    if (!array_key_exists($host, $this->map)) {
      throw new \RuntimeException('dns_unmapped');
    }
    return $this->map[$host];
  }

}
