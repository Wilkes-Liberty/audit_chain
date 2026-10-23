<?php

declare(strict_types=1);

namespace Drupal\audit_chain\Logger;

use Psr\Log\LoggerInterface;
use Psr\Log\LoggerTrait;

/**
 * Writes structured append events through PHP syslog.
 *
 * Used only when stream_exclude_dblog is on and no non-dblog logger
 * backend is available, so that opt-in still emits a parseable line on a
 * site that has Database Logging and nothing else. Not tagged as a Drupal
 * logger: that would put this sink on every channel, including the
 * audit_chain channel stream_enabled uses by default.
 *
 * The JSON object keeps the same context keys the previous
 * logger.channel.audit_chain info() call emitted, so a collector that keyed
 * on those fields does not have to be rewritten.
 */
final class PhpSyslogStreamLogger implements LoggerInterface {

  use LoggerTrait;

  /**
   * JSON flags matching AuditChainLogger's stored/streamed payloads.
   */
  private const JSON_FLAGS = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES;

  /**
   * Whether openlog() has been called for this request.
   */
  private bool $opened = FALSE;

  /**
   * {@inheritdoc}
   */
  public function log($level, string|\Stringable $message, array $context = []): void {
    $payload = [
      'message' => (string) $message,
      'channel' => $context['channel'] ?? NULL,
      'operation' => $context['operation'] ?? NULL,
      'uid' => $context['uid'] ?? NULL,
      'entity_type' => $context['entity_type'] ?? NULL,
      // Bundle is load-bearing for SIEM rules; see AuditChainLogger::append().
      'bundle' => $context['bundle'] ?? NULL,
      'entity_id' => $context['entity_id'] ?? NULL,
      'timestamp' => $context['timestamp'] ?? NULL,
      'row_hash' => $context['row_hash'] ?? NULL,
    ];
    $encoded = json_encode($payload, self::JSON_FLAGS);
    if ($encoded === FALSE) {
      // Still emit something a collector can grep; do not throw — a stream
      // failure must not roll back the chain row.
      $encoded = '{"message":"audit_chain_event","encode_failed":true}';
    }

    $this->write($encoded);
  }

  /**
   * Sends one line to syslog, opening the connection once per request.
   *
   * @param string $line
   *   A single structured record, already encoded.
   */
  private function write(string $line): void {
    if (!$this->opened) {
      // Identity is stable so syslog-ng / rsyslog can filter on program
      // name. LOG_ODELAY waits for the first write; LOG_PID distinguishes
      // PHP-FPM workers. A failed open still tries syslog() once — this
      // sink must not throw.
      openlog('audit_chain', LOG_ODELAY | LOG_PID, LOG_USER);
      $this->opened = TRUE;
    }
    syslog(LOG_INFO, $line);
  }

}
