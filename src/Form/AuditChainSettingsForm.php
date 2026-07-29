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

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $this->config('audit_chain.settings')
      ->set('hash_key', (string) $form_state->getValue('hash_key'))
      ->set('encryption_profile', (string) $form_state->getValue('encryption_profile'))
      ->set('stream_enabled', (bool) $form_state->getValue('stream_enabled'))
      ->save();

    parent::submitForm($form, $form_state);
  }

}
