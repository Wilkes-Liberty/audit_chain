<?php

declare(strict_types=1);

namespace Drupal\audit_chain\Hook;

use Drupal\audit_chain\AuditChainLoggerInterface;
use Drupal\audit_chain\AuditChainMetrics;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Datetime\DateFormatterInterface;
use Drupal\Core\Extension\Requirement\RequirementSeverity;
use Drupal\Core\Hook\Attribute\Hook;
use Drupal\Core\State\StateInterface;
use Drupal\Core\StringTranslation\StringTranslationTrait;

/**
 * Status-report findings for Audit Chain.
 *
 * Findings live on hook_runtime_requirements(): Drupal 13 stops calling the
 * procedural hook_requirements(), and a signing-key or verification finding
 * must not be able to leave the status report without an error. Drupal 10.6
 * still invokes the legacy hook; that bridge calls runtime() and is marked
 * #[LegacyRequirementsHook] so 11.3+ does not run both.
 */
final class AuditChainRequirements {

  use StringTranslationTrait;

  /**
   * Constructs the hook class.
   *
   * @param \Drupal\audit_chain\AuditChainLoggerInterface $logger
   *   Signing status and the prefix seal.
   * @param \Drupal\audit_chain\AuditChainMetrics $metrics
   *   Scheduled-verification snapshot (classify() stays the only classifier).
   * @param \Drupal\Core\Database\Connection $database
   *   The database (retired encryption-profile scan).
   * @param \Drupal\Core\State\StateInterface $state
   *   State storage (retention-refused flag).
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory (configured encryption profile).
   * @param \Drupal\Core\Datetime\DateFormatterInterface $dateFormatter
   *   Formats last-run time for classified states that have one.
   */
  public function __construct(
    private readonly AuditChainLoggerInterface $logger,
    private readonly AuditChainMetrics $metrics,
    private readonly Connection $database,
    private readonly StateInterface $state,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly DateFormatterInterface $dateFormatter,
  ) {}

  /**
   * Implements hook_runtime_requirements().
   *
   * Reports the one condition that otherwise has no signal anywhere: a signing
   * key that is configured but will not resolve. The chain keeps working when
   * that happens — it falls back to unkeyed SHA-256 — so nothing errors,
   * nothing is missing, and the site goes on believing its audit trail is
   * signed.
   *
   * Reported at ERROR rather than WARNING: the module's single headline
   * claim is that forging a repair requires the key. While this condition
   * holds, it does not.
   *
   * @return array<string, array<string, mixed>>
   *   Requirements keyed by id.
   */
  #[Hook('runtime_requirements')]
  public function runtime(): array {
    $requirements = [];

    // Runs on every path, including the two early returns below: a retired
    // encryption profile is independent of whether the chain is signed, and
    // hanging it off the key check would hide it on exactly the sites that
    // configured signing correctly.
    if ($this->state->get('audit_chain.retention_refused', FALSE)) {
      $requirements['audit_chain_retention'] = [
        'title' => $this->t('Audit Chain: retention requires review'),
        'value' => $this->t('Automatic deletion refused; audit records retained'),
        'severity' => self::severity('warn'),
        'description' => $this->t('A consumer requested deletion of expired audit records. Channels share one chain, so deleting those records would invalidate retained evidence. Review retention requirements and storage capacity. This warning does not mean the chain verifies; check the separate verification result.'),
      ];
    }

    $this->addEncryption($requirements);
    $this->addSeal($requirements);
    $this->addScheduledVerification($requirements);

    $status = $this->logger->signingStatus();
    if ($status['key_id'] === '') {
      // Unkeyed by choice. Documented behaviour, not a fault.
      return $requirements;
    }

    if ($status['keyed']) {
      return $requirements;
    }

    $requirements['audit_chain_hash_key'] = [
      'title' => $this->t('Audit Chain: signing key unresolvable'),
      'value' => $this->t("Key '@key' is configured but resolves to nothing", ['@key' => $status['key_id']]),
      'severity' => self::severity('crit'),
      'description' => $this->t("Every entry written while this holds is hashed with unkeyed SHA-256, so anyone with database access can edit a row and recompute the chain over it. Entries already written this way cannot be signed retrospectively — fix the Key entity, then run <code>drush audit-chain:verify</code>, which reports rows written unkeyed separately from tampering."),
    ];

    return $requirements;
  }

  /**
   * Status-report severity that works on Drupal 10.6 and 11.2+/12.
   *
   * RequirementSeverity exists from 11.2 and is required on 12 (the
   * REQUIREMENT_* integers are removed there). Drupal 10.6 still needs the
   * ints. enum_exists() is the same guard file_gate uses so a D10.6 floor
   * does not load a class that branch does not have.
   *
   * @param string $level
   *   One of ok, crit, warn.
   *
   * @return \Drupal\Core\Extension\Requirement\RequirementSeverity|int
   *   The enum on 11.2+ / 12, or the matching integer on 10.6.
   */
  public static function severity(string $level): mixed {
    if (enum_exists(RequirementSeverity::class)) {
      return match ($level) {
        'ok' => RequirementSeverity::OK,
        'crit' => RequirementSeverity::Error,
        'warn' => RequirementSeverity::Warning,
        default => RequirementSeverity::Warning,
      };
    }
    return match ($level) {
      'ok' => 0,
      'crit' => 2,
      'warn' => 1,
      default => 1,
    };
  }

  /**
   * Builds one scheduled-verification status-report row from a snapshot.
   *
   * Unknown reasons must not throw. They are not the pending-first-run card.
   *
   * @param array $snapshot
   *   Output of ScheduledVerificationPresentation::snapshot().
   *
   * @return array|null
   *   A hook_runtime_requirements row, or NULL when the classifier is silent.
   *
   * @phpstan-param array{
   *   presented: array{
   *     label: mixed,
   *     detail: mixed,
   *     severity: string,
   *     log_level: string|null,
   *     dispatch: bool,
   *     omit: bool,
   *     uses_time: bool
   *   },
   *   when?: string|null,
   *   ...
   * } $snapshot
   */
  public static function scheduledVerificationRequirement(array $snapshot): ?array {
    $presented = $snapshot['presented'];
    if ($presented['omit']) {
      return NULL;
    }
    $when = $snapshot['when'] ?? NULL;
    $when = is_string($when) && $when !== '' ? $when : NULL;
    $severity = self::severity(match ($presented['severity']) {
      'ok' => 'ok',
      'crit' => 'crit',
      'warn' => 'warn',
      default => 'warn',
    });
    $value = $presented['label'];
    if ($presented['uses_time'] && $when !== NULL) {
      $value = t('@label (last run @time)', [
        '@label' => $presented['label'],
        '@time' => $when,
      ]);
    }
    return [
      'title' => t('Audit Chain: scheduled verification'),
      'value' => $value,
      'severity' => $severity,
      'description' => $presented['detail'],
    ];
  }

  /**
   * Reports an active prefix seal (historical, not a live-chain failure).
   *
   * @param array $requirements
   *   The requirements array, added to by reference.
   */
  private function addSeal(array &$requirements): void {
    $seal = $this->logger->getSeal();
    if ($seal === NULL) {
      return;
    }
    $requirements['audit_chain_prefix_seal'] = [
      'title' => $this->t('Audit Chain: historical prefix sealed'),
      'value' => $this->t('Sealed through row id @id (@count chained hashes)', [
        '@id' => $seal['sealed_through_id'],
        '@count' => $seal['row_count'],
      ]),
      'severity' => self::severity('warn'),
      'description' => $this->t('A genesis seal freezes an unverifiable prefix so it is not re-chained. Content before that id is not re-checked; only that stored hashes are unchanged. Post-seal rows are still fully verified. Reason recorded: @reason. Run <code>drush audit-chain:verify</code> for the live verdict.', [
        '@reason' => $seal['reason'],
      ]),
    ];
  }

  /**
   * Reports entries encrypted under a profile the site no longer uses.
   *
   * @param array $requirements
   *   The requirements array, added to by reference.
   */
  private function addEncryption(array &$requirements): void {
    if (!$this->database->schema()->tableExists('audit_chain_log')
      || !$this->database->schema()->fieldExists('audit_chain_log', 'encryption_profile')) {
      // Mid-install, mid-uninstall, or before update 10002. A status check must
      // never itself crash.
      return;
    }

    $configured = (string) ($this->configFactory->get('audit_chain.settings')->get('encryption_profile') ?? '');

    // Existence, not a count: the index makes this cheap on a large table, and
    // the operator needs to know *that* it happened, not how many times.
    $query = $this->database->select('audit_chain_log', 'l');
    $query->fields('l', ['encryption_profile']);
    $query->isNotNull('l.encryption_profile');
    $query->condition('l.encryption_profile', '', '<>');
    $query->condition('l.encryption_profile', $configured, '<>');
    $stale = $query->range(0, 1)->execute()->fetchField();

    if ($stale === FALSE || $stale === NULL) {
      return;
    }

    $requirements['audit_chain_encryption_rotated'] = [
      'title' => $this->t('Audit Chain: entries encrypted under a retired profile'),
      'value' => $configured === ''
        ? $this->t("Rows were encrypted with '@old'; encryption is now off", [
          '@old' => $stale,
        ])
        : $this->t("Rows were encrypted with '@old'; the configured profile is '@new'", [
          '@old' => $stale,
          '@new' => $configured,
        ]),
      'severity' => self::severity('warn'),
      'description' => $this->t("The metadata on those entries cannot be decrypted with the profile configured now. The entries themselves are intact and the chain still verifies when the old profile entity is still loadable (each row records which profile produced its bytes). Run <code>drush audit-chain:reencrypt --from=PROFILE --to=PROFILE</code> to rewrite ciphertext to the current profile without touching hashes. Keep the previous EncryptionProfile until that finishes."),
    ];
  }

  /**
   * Reports the scheduled-verification health (d.o #3616535).
   *
   * Classification is ScheduledVerificationIntegrity::classify() via
   * ScheduledVerificationPresentation::snapshot(); this method maps that
   * snapshot onto requirement copy. The assurance-profile-without-schedule
   * warning is presentation: the classifier only sees interval and run.
   *
   * An integrity or assurance failure is an ERROR. A leading unsigned prefix
   * with a verifying signed successor is a documented WARNING: those rows stay
   * in the log and are not re-signed. A disclosed historical fork whose
   * successor segment verifies is a documented WARNING: whole-history
   * verification stays unsuccessful and rows are not rewritten. A missing
   * successor or segment_ok=false stays an ERROR. A foreign seal is a WARNING:
   * it remains unverified, but its copied prefix hashes have not changed. A
   * schedule that has gone quiet (no run within twice its interval) is a
   * WARNING — silence is not health. A confirmed witness the live chain no
   * longer contains is an ERROR (`chain_rewound`): a database restore can leave
   * the hashes consistent. A witness that cannot be read is a WARNING and does
   * not by itself fail the hash-chain result. Requiring keyed verification
   * while never scheduling it is also a WARNING: the assurance profile is only
   * as strong as its cadence.
   *
   * @param array $requirements
   *   The requirements array, added to by reference.
   */
  private function addScheduledVerification(array &$requirements): void {
    // snapshot() formats last-run time only for classified states that have
    // one; disabled/pending skip date.formatter so callers without system
    // date formats still render.
    $snapshot = $this->metrics->snapshot(
      fn (int $time): string => $this->dateFormatter->format($time),
    );
    $requirement = self::scheduledVerificationRequirement($snapshot);
    if ($requirement !== NULL) {
      $requirements['audit_chain_scheduled_verification'] = $requirement;
    }
  }

}
