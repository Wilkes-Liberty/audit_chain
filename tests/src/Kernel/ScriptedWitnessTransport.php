<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain\Kernel;

use Drupal\audit_chain\Witness\WitnessTransportInterface;

/**
 * HTTP double that returns scripted results and records calls.
 */
final class ScriptedWitnessTransport implements WitnessTransportInterface {

  /**
   * Recorded requests.
   *
   * @var list<array{method: string, url: string, body: string, headers: array<string, string>}>
   */
  public array $calls = [];

  /**
   * Scripted results, exceptions, or closures.
   *
   * @var list<array{status: int, body: string}|\Throwable|\Closure>
   */
  public array $script = [];

  /**
   * {@inheritdoc}
   */
  public function request(string $method, string $url, string $body, array $headers, int $maxBytes = 10000): array {
    $this->calls[] = [
      'method' => $method,
      'url' => $url,
      'body' => $body,
      'headers' => $headers,
    ];
    if ($this->script === []) {
      throw new \RuntimeException('unexpected_witness_request');
    }
    $next = array_shift($this->script);
    if ($next instanceof \Closure) {
      $next = $next();
    }
    if ($next instanceof \Throwable) {
      throw $next;
    }
    if (strlen($next['body']) > $maxBytes) {
      throw new \RuntimeException('response_too_large');
    }
    return $next;
  }

}
