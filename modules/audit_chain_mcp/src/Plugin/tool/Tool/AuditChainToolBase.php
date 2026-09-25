<?php

declare(strict_types=1);

namespace Drupal\audit_chain_mcp\Plugin\tool\Tool;

use Drupal\audit_chain\AuditChainLogger;
use Drupal\audit_chain\ScheduledVerifier;
use Drupal\Core\Access\AccessResult;
use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;
use Drupal\mcp_sentinel\Plugin\tool\Tool\McpEntityToolTrait;
use Drupal\mcp_sentinel\Plugin\tool\Tool\McpGovernedToolBase;
use Drupal\tool\ExecutableResult;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Shares access, rate limiting and refusal handling for Audit Chain tools.
 *
 * This module's own refusals are one fixed message. Caller input, exception
 * text, rows, metadata, hashes, MACs and key identifiers never reach a result.
 */
abstract class AuditChainToolBase extends McpGovernedToolBase {

  use McpEntityToolTrait;

  /**
   * Permission every tool in this module requires.
   */
  public const PERMISSION = 'use audit chain mcp tools';

  /**
   * Largest JSON result a tool returns, in bytes.
   *
   * The resolved profile's response-size cap applies when it is lower.
   */
  protected const MAX_RESULT_BYTES = 131072;

  /**
   * Verification reasons the module defines. Anything else reports as "other".
   */
  private const VERDICT_REASONS = [
    AuditChainLogger::REASON_TAMPERED,
    AuditChainLogger::REASON_WRITTEN_UNKEYED,
    AuditChainLogger::REASON_SEAL_BROKEN,
    AuditChainLogger::REASON_SEAL_FOREIGN,
    ScheduledVerifier::REASON_KEY_REQUIRED,
  ];

  /**
   * Successor reasons the module defines. Anything else reports as "other".
   */
  private const SUCCESSOR_REASONS = [
    'awaiting_verification',
    'historical_anchor_changed',
    'recovery_receipt_missing',
    'recovery_record_invalid',
    'recovery_record_missing',
    'recovery_status_unavailable',
    'successor_integrity_failed',
  ];

  /**
   * MCP Sentinel's exfiltration guard, when the installed version has one.
   *
   * @var \Drupal\mcp_sentinel\Service\McpExfiltrationGuard|null
   */
  protected $exfiltrationGuard = NULL;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->exfiltrationGuard = $container->has('mcp_sentinel.exfiltration_guard')
      ? $container->get('mcp_sentinel.exfiltration_guard')
      : NULL;
    return $instance;
  }

  /**
   * Runs the operation against the module's own services.
   *
   * @param array $values
   *   Input values.
   *
   * @return array
   *   Result without rows, metadata, hashes, MACs or key identifiers.
   *
   * @throws \InvalidArgumentException
   *   When an input is not acceptable. The message is never relayed.
   */
  abstract protected function run(array $values): array;

  /**
   * Additional permissions a tool requires beyond the shared one.
   *
   * @return string[]
   *   Permission names.
   */
  protected function extraPermissions(): array {
    return [];
  }

  /**
   * {@inheritdoc}
   */
  protected function checkGovernedDiscoveryAccess(AccountInterface $account): AccessResultInterface {
    return $this->checkGovernedAccess([], $account);
  }

  /**
   * {@inheritdoc}
   */
  protected function checkGovernedAccess(array $values, AccountInterface $account): AccessResultInterface {
    return AccessResult::allowedIfHasPermissions(
      $account,
      array_merge([self::PERMISSION], $this->extraPermissions()),
    )->setCacheMaxAge(0);
  }

  /**
   * {@inheritdoc}
   */
  protected function doExecute(array $values): ExecutableResult {
    try {
      // ToolBase::execute() does not call access(). Recheck for PHP callers.
      if (!$this->checkAccess($values, $this->currentUser)) {
        return $this->refused();
      }
      $profile = $this->governancePolicyResolver?->resolve($this->currentUser);
      if ($profile === NULL) {
        return $this->refused();
      }
      if ($limited = $this->checkRateLimit($profile, $this->getPluginId())) {
        return $limited;
      }
      $result = $this->run($values);
      if (strlen(json_encode($result, JSON_THROW_ON_ERROR)) > $this->resultLimit($profile)) {
        return $this->refused();
      }
      return ExecutableResult::success($this->t('Audit Chain operation completed.'), $result);
    }
    catch (\Throwable $exception) {
      // Record the failure class only. Messages can carry caller input.
      $this->logger->warning('Audit Chain tool @tool failed with @type at @source:@line.', [
        '@tool' => $this->getPluginId(),
        '@type' => get_class($exception),
        '@source' => basename($exception->getFile()),
        '@line' => $exception->getLine(),
      ]);
      return $this->refused();
    }
  }

  /**
   * The smaller of this module's ceiling and the profile's response-size cap.
   */
  protected function resultLimit(McpPolicyProfileInterface $profile): int {
    $cap = $this->exfiltrationGuard !== NULL
      ? (int) $this->exfiltrationGuard->effectiveResponseSizeCap($profile)
      : 0;
    return $cap > 0 ? min(static::MAX_RESULT_BYTES, $cap) : static::MAX_RESULT_BYTES;
  }

  /**
   * The refusal this module's own code returns.
   */
  protected function refused(): ExecutableResult {
    return ExecutableResult::failure($this->t('Audit Chain operation refused. Check permissions, inputs and limits.'));
  }

  /**
   * Reduces a stored verification run to its verdict fields.
   *
   * The run record is rebuilt field by field, so nothing a later version adds
   * to it reaches a result unreviewed.
   *
   * @param mixed $run
   *   The scheduled-verification state value.
   *
   * @return array|null
   *   The verdict fields, or NULL when no run is recorded.
   */
  protected function verdictFields(mixed $run): ?array {
    if (!is_array($run)) {
      return NULL;
    }
    $verdict = is_array($run['verdict'] ?? NULL) ? $run['verdict'] : [];
    return [
      'time' => self::intOrNull($run['time'] ?? NULL),
      'ok' => ($run['ok'] ?? FALSE) === TRUE,
      'reason' => self::reason($run['reason'] ?? NULL, self::VERDICT_REASONS),
      'keyed' => ($run['keyed'] ?? FALSE) === TRUE,
      'broken_at' => self::intOrNull($verdict['broken_at'] ?? NULL),
      'unkeyed_rows' => (int) ($verdict['unkeyed_rows'] ?? 0),
      'unkeyed_through' => self::intOrNull($verdict['unkeyed_through'] ?? NULL),
      'verified_from' => self::intOrNull($verdict['verified_from'] ?? NULL),
      'sealed_through' => self::intOrNull($verdict['sealed_through'] ?? NULL),
      'seal_intact' => is_bool($verdict['seal_intact'] ?? NULL) ? $verdict['seal_intact'] : NULL,
    ];
  }

  /**
   * Reduces a successor status to its verdict fields.
   *
   * The incident reference, segment id and historical verdict stay out: the
   * first is operator free text and the others identify evidence records.
   *
   * @param mixed $successor
   *   The successor status from a run record.
   *
   * @return array|null
   *   The successor fields, or NULL when no recovery segment exists.
   */
  protected function successorFields(mixed $successor): ?array {
    if (!is_array($successor)) {
      return NULL;
    }
    return [
      'segment_ok' => ($successor['segment_ok'] ?? FALSE) === TRUE,
      'historical_ok' => ($successor['historical_ok'] ?? FALSE) === TRUE,
      'reason' => self::reason($successor['reason'] ?? NULL, self::SUCCESSOR_REASONS),
      'verified_rows' => self::intOrNull($successor['verified_rows'] ?? NULL),
    ];
  }

  /**
   * Maps a stored reason onto the module's own reason keys.
   */
  private static function reason(mixed $reason, array $known): ?string {
    if ($reason === NULL || $reason === '') {
      return NULL;
    }
    return in_array($reason, $known, TRUE) ? $reason : 'other';
  }

  /**
   * Casts a stored number, keeping NULL.
   */
  private static function intOrNull(mixed $value): ?int {
    return is_numeric($value) ? (int) $value : NULL;
  }

}
