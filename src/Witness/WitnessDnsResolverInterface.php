<?php

declare(strict_types=1);

namespace Drupal\audit_chain\Witness;

/**
 * Resolves a witness destination to the addresses that would be contacted.
 */
interface WitnessDnsResolverInterface {

  /**
   * Returns the A and AAAA records for a host.
   *
   * @param string $host
   *   Lowercase hostname with no port.
   *
   * @return list<string>
   *   Addresses that would be contacted. Empty when lookup fails.
   */
  public function resolve(string $host): array;

}
