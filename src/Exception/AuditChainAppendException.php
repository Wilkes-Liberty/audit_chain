<?php

declare(strict_types=1);

namespace Drupal\audit_chain\Exception;

/**
 * Thrown when an append cannot be serialised through commit.
 *
 * Both {@see \Drupal\audit_chain\AuditChainLoggerInterface::log()} and
 * {@see \Drupal\audit_chain\AuditChainLoggerInterface::logKeyed()} throw this
 * and write nothing when the chain mutex is missing. A deadlock or lock
 * timeout surfaces as the underlying database exception instead — still a
 * refused write, not a fork. Evidence-required callers must treat either as
 * a failed precommit.
 */
final class AuditChainAppendException extends \RuntimeException {
}
