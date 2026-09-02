<?php

declare(strict_types=1);

namespace Drupal\audit_chain\Exception;

/**
 * Thrown when a keyed append is required but no signing key will resolve.
 *
 * Ordinary {@see \Drupal\audit_chain\AuditChainLoggerInterface::log()} still
 * writes an unkeyed row in that situation — an unsigned entry beats a lost
 * one. Evidence-required consumers need the opposite: refuse the action
 * rather than record an unsigned precommit. {@see
 * \Drupal\audit_chain\AuditChainLoggerInterface::logKeyed()} throws this
 * and writes nothing.
 */
final class AuditChainSigningUnavailableException extends \RuntimeException {
}
