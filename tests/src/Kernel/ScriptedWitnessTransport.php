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
   * An item may include match, url, or method so a later backend cannot
   * consume a response queued for a different host. Items without those
   * keys stay first-in, first-out.
   *
   * @var list<array{status: int, body: string, match?: string, url?: string, method?: string}|\Throwable|\Closure>
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
    $next = $this->consume($method, $url);
    if ($next instanceof \Closure) {
      $next = $next();
    }
    if ($next instanceof \Throwable) {
      throw $next;
    }
    if (!is_array($next) || !isset($next['status'], $next['body']) || !is_int($next['status']) || !is_string($next['body'])) {
      throw new \RuntimeException('unexpected_witness_request');
    }
    if (strlen($next['body']) > $maxBytes) {
      throw new \RuntimeException('response_too_large');
    }
    return [
      'status' => $next['status'],
      'body' => $next['body'],
    ];
  }

  /**
   * Takes the next scripted result that matches this request.
   */
  private function consume(string $method, string $url): mixed {
    foreach ($this->script as $index => $item) {
      if (!$this->matches($item, $method, $url)) {
        continue;
      }
      array_splice($this->script, $index, 1);
      return $item;
    }
    throw new \RuntimeException('unexpected_witness_request');
  }

  /**
   * Whether a scripted item is eligible for this request.
   */
  private function matches(mixed $item, string $method, string $url): bool {
    if ($item instanceof \Closure || $item instanceof \Throwable) {
      return TRUE;
    }
    if (!is_array($item)) {
      return FALSE;
    }
    if (isset($item['match']) && is_string($item['match']) && !str_contains($url, $item['match'])) {
      return FALSE;
    }
    if (isset($item['url']) && is_string($item['url']) && $item['url'] !== $url && !str_contains($url, $item['url'])) {
      return FALSE;
    }
    if (isset($item['method']) && is_string($item['method']) && strtoupper($item['method']) !== strtoupper($method)) {
      return FALSE;
    }
    return TRUE;
  }

}
