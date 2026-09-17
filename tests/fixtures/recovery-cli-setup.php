<?php

/**
 * @file
 * Creates an authenticated synthetic fork on a disposable CLI test site.
 */

use Drupal\audit_chain\AuditChainLogger;
use Drupal\key\Entity\Key;

if (getenv('AUDIT_CHAIN_CLI_TEST') !== '1') {
  throw new RuntimeException('Disposable CLI fixture only.');
}
Key::create([
  'id' => 'recovery_cli_key',
  'label' => 'Synthetic CLI key',
  'key_type' => 'authentication',
  'key_provider' => 'config',
  'key_provider_settings' => ['key_value' => 'synthetic-cli-test-key'],
])->save();
\Drupal::configFactory()->getEditable('audit_chain.settings')
  ->set('hash_key', 'recovery_cli_key')->save();
$chain = \Drupal::service('audit_chain.logger');
foreach (['root', 'left', 'right'] as $operation) {
  $chain->logKeyed('cli_test', $operation);
}
$db = \Drupal::database();
$rows = $db->select('audit_chain_log', 'a')->fields('a')
  ->orderBy('id', 'DESC')->range(0, 3)->execute()->fetchAll();
$right = (array) $rows[0];
$right['prev_hash'] = $rows[2]->row_hash;
// Reuse the real canonical encoding; fault injection stays in this fixture.
$canonical = new ReflectionMethod(AuditChainLogger::class, 'canonicalFromRecord');
$right['row_hash'] = hash_hmac(
  'sha256',
  $right['prev_hash'] . '|' . $canonical->invoke($chain, $right),
  'synthetic-cli-test-key',
);
$db->update('audit_chain_log')
  ->fields(['prev_hash' => $right['prev_hash'], 'row_hash' => $right['row_hash']])
  ->condition('id', $right['id'])->execute();
if ($chain->verify()['ok']) {
  throw new RuntimeException('Synthetic fork must fail whole-history verification.');
}
