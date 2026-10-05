<?php

declare(strict_types=1);

namespace Drupal\audit_chain\Witness;

/**
 * Rejects witness destinations that are not public HTTPS on an allowlist.
 *
 * A redirect is never requested. Name resolution must be public unicast,
 * including rejection of loopback, private, link-local, multicast,
 * unspecified, carrier-grade NAT, and IPv4-mapped equivalents.
 */
final class DestinationPolicy {

  public function __construct(
    private readonly WitnessDnsResolverInterface $dns,
  ) {}

  /**
   * Checks one absolute URL against the allowed hosts.
   *
   * @param string $url
   *   Absolute URL the client is about to request.
   * @param list<string> $allowedHosts
   *   Lowercase hostnames that may be contacted.
   */
  public function assertAllowed(string $url, array $allowedHosts): void {
    $parts = parse_url($url);
    if (!is_array($parts)) {
      throw new \RuntimeException('witness_destination_rejected');
    }
    if (($parts['scheme'] ?? '') !== 'https') {
      throw new \RuntimeException('witness_destination_rejected');
    }
    if (isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])) {
      throw new \RuntimeException('witness_destination_rejected');
    }
    if (isset($parts['port']) && (int) $parts['port'] !== 443) {
      throw new \RuntimeException('witness_destination_rejected');
    }
    $host = strtolower((string) ($parts['host'] ?? ''));
    if ($host === '' || !in_array($host, $allowedHosts, TRUE)) {
      throw new \RuntimeException('witness_destination_rejected');
    }
    $addresses = $this->dns->resolve($host);
    if ($addresses === []) {
      throw new \RuntimeException('witness_destination_rejected');
    }
    foreach ($addresses as $address) {
      if (!$this->isPublicUnicast($address)) {
        throw new \RuntimeException('witness_destination_rejected');
      }
    }
  }

  /**
   * Returns the lowercase host of an https URL, or rejects it.
   */
  public static function host(string $url): string {
    $host = parse_url($url, PHP_URL_HOST);
    if (!is_string($host) || $host === '') {
      throw new \RuntimeException('witness_destination_rejected');
    }
    return strtolower($host);
  }

  /**
   * Whether an address is a public unicast address.
   */
  private function isPublicUnicast(string $address): bool {
    $mapped = $this->mappedV4($address);
    if ($mapped !== NULL) {
      return $this->isPublicUnicast($mapped);
    }
    if (str_contains($address, ':')) {
      $valid = filter_var(
        $address,
        FILTER_VALIDATE_IP,
        FILTER_FLAG_IPV6 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
      );
      if ($valid === FALSE) {
        return FALSE;
      }
      return !str_starts_with(strtolower($address), 'ff');
    }
    $valid = filter_var(
      $address,
      FILTER_VALIDATE_IP,
      FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
    );
    if ($valid === FALSE) {
      return FALSE;
    }
    $numeric = ip2long($address);
    if ($numeric === FALSE) {
      return FALSE;
    }
    $cgnat = ip2long('100.64.0.0');
    return $cgnat !== FALSE && ($numeric & 0xffc00000) !== $cgnat;
  }

  /**
   * Extracts an IPv4 address embedded in an IPv4-mapped IPv6 address.
   */
  private function mappedV4(string $address): ?string {
    if (preg_match('/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i', $address, $matches) === 1) {
      return $matches[1];
    }
    $packed = @inet_pton($address);
    if ($packed === FALSE || strlen($packed) !== 16) {
      return NULL;
    }
    $prefix = substr($packed, 0, 12);
    if ($prefix === "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff") {
      $mapped = inet_ntop(substr($packed, 12));
      return $mapped === FALSE ? NULL : $mapped;
    }
    return NULL;
  }

}
