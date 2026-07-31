<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain\Kernel;

use Drupal\audit_chain\AuditChainCollector;
use Drupal\KernelTests\KernelTestBase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel tests for the request-scoped collector.
 *
 * The collector exists because the obvious integration is the destructive one:
 * a consumer logging from `hook_entity_field_access()` turns one human action
 * into dozens of chain rows, and a flooded hash chain cannot be un-flooded.
 */
#[CoversClass(AuditChainCollector::class)]
#[Group('audit_chain')]
#[RunTestsInSeparateProcesses]
final class AuditChainCollectorTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['system', 'user', 'key', 'encrypt', 'audit_chain'];

  /**
   * The collector under test.
   */
  private AuditChainCollector $collector;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installSchema('audit_chain', ['audit_chain_log']);
    $this->installConfig(['audit_chain']);
    $this->collector = $this->container->get('audit_chain.collector');
  }

  /**
   * Returns all stored rows in insertion order.
   *
   * @return array<int, object>
   *   The rows.
   */
  private function rows(): array {
    return $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l')
      ->orderBy('id')
      ->execute()
      ->fetchAll();
  }

  /**
   * Nothing reaches the chain until the flush.
   *
   * This is the whole point: the write happens once, after the request, not on
   * every call.
   */
  public function testCollectingWritesNothingUntilFlush(): void {
    $this->collector->collect('personnel', 'field_read', ['entity_type' => 'node', 'id' => '1']);
    $this->assertSame(1, $this->collector->count());
    $this->assertCount(0, $this->rows(), 'Collecting must not write.');

    $this->assertSame(1, $this->collector->flush());
    $this->assertCount(1, $this->rows());
  }

  /**
   * Repeated checks on the same target collapse to one entry.
   *
   * The realistic shape: a field-access hook firing once per field, per render.
   */
  public function testRepeatedChecksOnOneTargetCollapse(): void {
    foreach (['field_salary', 'field_ssn', 'field_dob', 'field_salary'] as $field) {
      $this->collector->collect('personnel', 'field_read', [
        'entity_type' => 'node',
        'id' => '42',
        'field' => $field,
      ]);
    }

    $this->assertSame(1, $this->collector->count(), 'Four checks on one node are one event.');
    $this->collector->flush();

    $rows = $this->rows();
    $this->assertCount(1, $rows);
    $this->assertSame('42', $rows[0]->entity_id);
  }

  /**
   * The first occurrence's metadata is kept, not the last, and not merged.
   *
   * Merging would invent a record of something nobody did: forty reads of one
   * node is still one read event, and a synthesised union of their metadata
   * describes no actual action.
   */
  public function testFirstOccurrenceWins(): void {
    $this->collector->collect('personnel', 'field_read', ['entity_type' => 'node', 'id' => '7', 'field' => 'first']);
    $this->collector->collect('personnel', 'field_read', ['entity_type' => 'node', 'id' => '7', 'field' => 'second']);
    $this->collector->flush();

    $rows = $this->rows();
    $this->assertCount(1, $rows);
    $this->assertSame(
      ['field' => 'first'],
      $this->container->get('audit_chain.logger')->decodeMetadata((string) $rows[0]->metadata),
    );
  }

  /**
   * Distinct targets stay distinct.
   */
  public function testDistinctTargetsAreNotCollapsed(): void {
    $this->collector->collect('personnel', 'field_read', ['entity_type' => 'node', 'id' => '1']);
    $this->collector->collect('personnel', 'field_read', ['entity_type' => 'node', 'id' => '2']);
    $this->collector->collect('personnel', 'entity_delete', ['entity_type' => 'node', 'id' => '1']);
    $this->collector->collect('mcp_sentinel', 'field_read', ['entity_type' => 'node', 'id' => '1']);

    $this->assertSame(4, $this->collector->count());
    $this->assertSame(4, $this->collector->flush());
    $this->assertCount(4, $this->rows());
  }

  /**
   * An explicit dedup key overrides the default.
   */
  public function testExplicitDedupeKeyOverridesTheDefault(): void {
    $this->collector->collect('personnel', 'field_read', ['entity_type' => 'node', 'id' => '1'], 'whole-request');
    $this->collector->collect('personnel', 'entity_delete', ['entity_type' => 'user', 'id' => '9'], 'whole-request');

    $this->assertSame(1, $this->collector->count(), 'One key means one entry, however different the calls.');
  }

  /**
   * Flushing twice cannot double-write.
   *
   * The subscriber fires on kernel.terminate, but a consumer may also flush
   * explicitly; neither should produce duplicate evidence.
   */
  public function testFlushingTwiceDoesNotDoubleWrite(): void {
    $this->collector->collect('personnel', 'field_read', ['entity_type' => 'node', 'id' => '1']);

    $this->assertSame(1, $this->collector->flush());
    $this->assertSame(0, $this->collector->flush(), 'The buffer is empty the second time.');
    $this->assertCount(1, $this->rows());
  }

  /**
   * Flushed entries form a valid chain.
   *
   * Deferring the write must not weaken the guarantee the module exists for.
   */
  public function testFlushedEntriesVerify(): void {
    $this->collector->collect('personnel', 'field_read', ['entity_type' => 'node', 'id' => '1']);
    $this->collector->collect('personnel', 'field_read', ['entity_type' => 'node', 'id' => '2']);
    $this->collector->flush();

    $this->assertTrue($this->container->get('audit_chain.logger')->verify()['ok']);
  }

}
