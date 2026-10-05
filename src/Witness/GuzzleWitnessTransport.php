<?php

declare(strict_types=1);

namespace Drupal\audit_chain\Witness;

use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;

/**
 * HTTP transport that refuses redirects and bounds time and body size.
 */
final class GuzzleWitnessTransport implements WitnessTransportInterface {

  public function __construct(
    private readonly ClientInterface $httpClient,
  ) {}

  /**
   * {@inheritdoc}
   */
  public function request(string $method, string $url, string $body, array $headers, int $maxBytes = 10000): array {
    $headers['User-Agent'] = 'audit_chain';
    try {
      $response = $this->httpClient->request($method, $url, [
        'headers' => $headers,
        'body' => $body,
        'allow_redirects' => FALSE,
        'connect_timeout' => 5,
        'timeout' => 15,
        'http_errors' => FALSE,
      ]);
    }
    catch (GuzzleException $exception) {
      throw new \RuntimeException('backend_unreachable', 0, $exception);
    }
    $raw = $response->getBody()->read($maxBytes + 1);
    if (strlen($raw) > $maxBytes) {
      throw new \RuntimeException('response_too_large');
    }
    return [
      'status' => $response->getStatusCode(),
      'body' => $raw,
    ];
  }

}
