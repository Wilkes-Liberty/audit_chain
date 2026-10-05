<?php

declare(strict_types=1);

namespace Drupal\audit_chain\Witness;

/**
 * Bounded HTTP transport for witness clients.
 */
interface WitnessTransportInterface {

  /**
   * Performs one request and returns the status and body.
   *
   * Redirects are not followed. A transport failure throws.
   *
   * @param string $method
   *   HTTP method.
   * @param string $url
   *   Absolute URL already accepted by destination policy.
   * @param string $body
   *   Request body. Empty for a read.
   * @param array<string, string> $headers
   *   Headers supplied by the witness client.
   * @param int $maxBytes
   *   Maximum response body accepted before failure.
   *
   * @return array{status: int, body: string}
   *   HTTP status and the bounded response body.
   */
  public function request(string $method, string $url, string $body, array $headers, int $maxBytes = 10000): array;

}
