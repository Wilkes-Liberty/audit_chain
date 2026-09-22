<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain\Kernel;

/**
 * Installs audit-chain tables including the append mutex.
 */
trait AuditChainSchemaTrait {

  /**
   * Installs the log table and seeds the singleton serialization row.
   *
   * Kernel tests enable the module without hook_install(), so the mutex row
   * that a real install inserts has to be created here.
   */
  protected function installAuditChainTables(): void {
    $this->installSchema('audit_chain', [
      'audit_chain_log',
      'audit_chain_mutex',
      'audit_chain_recovery',
      'audit_chain_checkpoint',
      'audit_chain_witness_receipt',
    ]);
    $this->container->get('database')->insert('audit_chain_mutex')
      ->fields(['id' => 1, 'locked' => 1])
      ->execute();
  }

}
