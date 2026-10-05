<?php

declare(strict_types=1);

namespace Drupal\audit_chain\Witness;

/**
 * Resolves witness hosts with PHP DNS lookups.
 */
final class PhpWitnessDnsResolver implements WitnessDnsResolverInterface {

  /**
   * {@inheritdoc}
   */
  public function resolve(string $host): array {
    $records = @dns_get_record($host, DNS_A + DNS_AAAA);
    if (!is_array($records)) {
      return [];
    }
    $addresses = [];
    foreach ($records as $record) {
      if (isset($record['ip']) && is_string($record['ip'])) {
        $addresses[] = $record['ip'];
      }
      if (isset($record['ipv6']) && is_string($record['ipv6'])) {
        $addresses[] = $record['ipv6'];
      }
    }
    return $addresses;
  }

}
