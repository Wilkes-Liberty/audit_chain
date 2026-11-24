<?php

declare(strict_types=1);

namespace Drupal\audit_chain;

use Drupal\Core\Database\Connection;

/**
 * Single-row id lookups on audit_chain_log that the primary key serves.
 *
 * Do not write these as orderBy('id', 'DESC')->range(0, 1). Drupal's pgsql
 * driver renders that ordering as "DESC NULLS LAST" (and ASC as "ASC NULLS
 * FIRST"), which the ascending primary key cannot serve, so PostgreSQL scans
 * and sorts the whole table to return one row. MIN() and MAX() on the key
 * are answered from the index on PostgreSQL, MySQL and SQLite alike.
 *
 * @internal
 */
final class LogRowLookup {

  /**
   * Returns the highest row id, or 0 when no row matches.
   *
   * @param \Drupal\Core\Database\Connection $database
   *   The connection.
   * @param int|null $throughId
   *   Only consider ids up to and including this one.
   * @param bool $chainedOnly
   *   Only consider rows with a non-empty row_hash.
   */
  public static function lastId(Connection $database, ?int $throughId = NULL, bool $chainedOnly = FALSE): int {
    $query = $database->select('audit_chain_log', 'l');
    $query->addExpression('MAX(l.id)', 'id');
    if ($throughId !== NULL) {
      $query->condition('l.id', $throughId, '<=');
    }
    if ($chainedOnly) {
      $query->isNotNull('l.row_hash')->condition('l.row_hash', '', '<>');
    }
    $id = $query->execute()->fetchField();
    return ($id === FALSE || $id === NULL) ? 0 : (int) $id;
  }

  /**
   * Returns the lowest row id greater than $afterId, or NULL when none.
   */
  public static function firstIdAfter(Connection $database, int $afterId): ?int {
    $query = $database->select('audit_chain_log', 'l');
    $query->addExpression('MIN(l.id)', 'id');
    $query->condition('l.id', $afterId, '>');
    $id = $query->execute()->fetchField();
    return ($id === FALSE || $id === NULL) ? NULL : (int) $id;
  }

}
