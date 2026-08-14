<?php

declare(strict_types=1);

namespace Drupal\audit_chain\Form;

use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\encrypt\EncryptionProfileManagerInterface;
use Drupal\key\KeyRepositoryInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Settings for the tamper-evident audit chain.
 */
final class AuditChainSettingsForm extends ConfigFormBase {

  /**
   * The Key repository.
   */
  protected KeyRepositoryInterface $keyRepository;

  /**
   * The encryption profile manager.
   */
  protected EncryptionProfileManagerInterface $encryptionProfileManager;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    $instance = parent::create($container);
    $instance->keyRepository = $container->get('key.repository');
    $instance->encryptionProfileManager = $container->get('encrypt.encryption_profile.manager');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames(): array {
    return ['audit_chain.settings'];
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'audit_chain_settings';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {
    $config = $this->config('audit_chain.settings');

    $keyOptions = ['' => $this->t('- None (unkeyed SHA-256) -')];
    foreach ($this->keyRepository->getKeys() as $id => $key) {
      $keyOptions[$id] = (string) $key->label();
    }

    $form['hash_key'] = [
      '#type' => 'select',
      '#title' => $this->t('Signing key'),
      '#options' => $keyOptions,
      '#default_value' => (string) ($config->get('hash_key') ?? ''),
      '#description' => $this->t('Without a key the chain is plain SHA-256: it detects accidental corruption and careless edits, but anyone with database access can recompute it after a change. With a key, forging a repair also requires the key — so store it outside the database (a File or Environment key provider).'),
    ];

    $retiredOptions = $keyOptions;
    unset($retiredOptions['']);
    $form['previous_hash_keys'] = [
      '#type' => 'select',
      '#multiple' => TRUE,
      '#title' => $this->t('Retired signing keys'),
      '#options' => $retiredOptions,
      '#default_value' => array_values((array) ($config->get('previous_hash_keys') ?? [])),
      '#access' => $retiredOptions !== [],
      '#description' => $this->t('Keys this chain was signed with previously. Verification accepts a row signed by any of them, so rotating the signing key does not make every earlier row look tampered with. Leave empty unless you have rotated. Removing a key from this list makes the rows it signed unverifiable.'),
    ];

    $profileOptions = ['' => $this->t('- None (metadata stored as plaintext) -')];
    foreach ($this->encryptionProfileManager->getAllEncryptionProfiles() as $id => $profile) {
      $profileOptions[$id] = (string) $profile->label();
    }

    $form['encryption_profile'] = [
      '#type' => 'select',
      '#title' => $this->t('Encrypt metadata at rest'),
      '#options' => $profileOptions,
      '#default_value' => (string) ($config->get('encryption_profile') ?? ''),
      '#description' => $this->t('<strong>Rotating this orphans existing rows.</strong> Metadata encrypted under one profile cannot be decrypted after switching to another, and the chain is computed over the plaintext — so those rows stop verifying. Export or re-encrypt before changing it.'),
    ];

    $form['stream_enabled'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Stream entries to the logger channel'),
      '#default_value' => (bool) $config->get('stream_enabled'),
      '#description' => $this->t('Emits each entry to the <code>audit_chain</code> channel as a structured record, so syslog or Monolog can forward it to a SIEM without polling the table.'),
    ];

    $form['verify_interval'] = [
      '#type' => 'number',
      '#title' => $this->t('Scheduled verification interval (seconds)'),
      '#min' => 0,
      '#default_value' => (int) $config->get('verify_interval'),
      '#description' => $this->t('Run a full chain verification on cron at most this often. <code>0</code> disables the schedule. A failed run is recorded on the status report, logged to the <code>audit_chain</code> channel, and dispatched as an event for alerting consumers — the chain itself is never modified.'),
    ];

    $form['verify_require_keyed'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Require keyed (HMAC) verification'),
      '#default_value' => (bool) $config->get('verify_require_keyed'),
      '#description' => $this->t('The enterprise assurance profile: scheduled verification fails — instead of falling back to unkeyed SHA-256 — when no signing key is configured or when rows were written unkeyed. Pair with a signing key and a verification interval.'),
    ];

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $this->config('audit_chain.settings')
      ->set('hash_key', (string) $form_state->getValue('hash_key'))
      ->set('previous_hash_keys', array_values(array_filter((array) $form_state->getValue('previous_hash_keys'))))
      ->set('encryption_profile', (string) $form_state->getValue('encryption_profile'))
      ->set('stream_enabled', (bool) $form_state->getValue('stream_enabled'))
      ->set('verify_interval', (int) $form_state->getValue('verify_interval'))
      ->set('verify_require_keyed', (bool) $form_state->getValue('verify_require_keyed'))
      ->save();

    parent::submitForm($form, $form_state);
  }

}
