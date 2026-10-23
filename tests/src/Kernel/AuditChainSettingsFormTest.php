<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain\Kernel;

use Drupal\audit_chain\Form\AuditChainSettingsForm;
use Drupal\Core\Form\FormState;
use Drupal\Core\Url;
use Drupal\KernelTests\KernelTestBase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;

/**
 * Kernel tests for settings-form encryption copy and export pairing.
 *
 * @coversDefaultClass \Drupal\audit_chain\Form\AuditChainSettingsForm
 *
 * @group audit_chain
 */
#[CoversClass(AuditChainSettingsForm::class)]
#[Group('audit_chain')]
final class AuditChainSettingsFormTest extends KernelTestBase {

  use AuditChainSchemaTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system',
    'user',
    'key',
    'encrypt',
    'audit_chain',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installAuditChainTables();
    $this->installEntitySchema('user');
    $this->installSchema('user', ['users_data']);
    $this->installConfig(['system', 'user', 'audit_chain']);
  }

  /**
   * Rotation copy matches README/status: hashes still verify.
   *
   * @covers ::buildForm
   */
  public function testEncryptionCopyDoesNotClaimRowsStopVerifying(): void {
    $form_object = AuditChainSettingsForm::create($this->container);
    $form_state = new FormState();
    $form = $form_object->buildForm([], $form_state);
    $description = (string) $form['encryption_profile']['#description'];

    $this->assertStringNotContainsString('stop verifying', $description);
    $this->assertStringContainsString('plaintext', $description);
    $this->assertStringContainsString('loadable', $description);
    $this->assertStringContainsString('drush audit-chain:reencrypt', $description);
  }

  /**
   * Stream copy names the 1.12.2 channel; dblog exclusion is the opt-in.
   *
   * @covers ::buildForm
   */
  public function testStreamCopyNamesTheChannelAndOptionalDblogExclusion(): void {
    $form_object = AuditChainSettingsForm::create($this->container);
    $form_state = new FormState();
    $form = $form_object->buildForm([], $form_state);
    $enabled = (string) $form['stream_enabled']['#description'];
    $this->assertStringContainsString('audit_chain', $enabled);
    $this->assertStringContainsString('audit_chain_event', $enabled);
    $this->assertStringNotContainsString('no update hook', $enabled);

    $exclude = (string) $form['stream_exclude_dblog']['#description'];
    $this->assertStringContainsString('Database Logging', $exclude);
    $this->assertStringContainsString('Reports → Audit Chain', $exclude);
    $this->assertStringContainsString(Url::fromRoute('audit_chain.dashboard')->toString(), $exclude);
  }

  /**
   * Enabled cron export without a destination is refused.
   *
   * @covers ::validateForm
   */
  public function testEnabledExportRequiresDestination(): void {
    $errors = $this->validateExport(TRUE, '');
    $this->assertArrayHasKey('export_destination', $errors);
  }

  /**
   * Destination pairing mirrors EvidenceExporter insecure-HTTP rules.
   *
   * @covers ::validateForm
   */
  public function testExportDestinationFollowsExporterRules(): void {
    $this->assertArrayHasKey(
      'export_destination',
      $this->validateExport(TRUE, 'http://collector.example.test/ingest'),
      'Off-host HTTP must be refused, matching REASON_INSECURE_DESTINATION.',
    );
    $this->assertSame([], $this->validateExport(TRUE, 'http://127.0.0.1:8125/ingest'));
    $this->assertSame([], $this->validateExport(TRUE, 'http://localhost/ingest'));
    $this->assertSame([], $this->validateExport(TRUE, 'https://evidence.example.test/ingest'));
    $this->assertSame([], $this->validateExport(TRUE, '/var/evidence/chain.ndjson'));
    $this->assertSame([], $this->validateExport(FALSE, ''));
    $this->assertArrayHasKey(
      'export_destination',
      $this->validateExport(FALSE, 'http://collector.example.test/ingest'),
      'An insecure destination is refused even when cron export is off.',
    );
  }

  /**
   * Runs validateForm() for one export_enabled / destination pair.
   *
   * @return array<string, mixed>
   *   Form-state errors keyed by element name.
   */
  private function validateExport(bool $enabled, string $destination): array {
    $form_object = AuditChainSettingsForm::create($this->container);
    $form_state = new FormState();
    $form = $form_object->buildForm([], $form_state);
    $form_state->setValues([
      'export_enabled' => $enabled,
      'export_destination' => $destination,
    ]);
    $form_object->validateForm($form, $form_state);
    return $form_state->getErrors();
  }

}
