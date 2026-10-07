<?php

declare(strict_types=1);

namespace Drupal\audit_chain\Drush\Commands;

use Drupal\audit_chain\ChainGap;
use Drush\Attributes as CLI;
use Drush\Commands\AutowireTrait;
use Drush\Commands\DrushCommands;
use Drush\Drush;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Records a known gap. Does not rewrite rows or open a second recovery.
 */
final class GapCommands extends DrushCommands {

  use AutowireTrait;

  public function __construct(
    #[Autowire(service: 'audit_chain.chain_gap')]
    private readonly ChainGap $gaps,
  ) {
    parent::__construct();
  }

  /**
   * Review a gap statement without writing it.
   */
  #[CLI\Command(name: 'audit-chain:gap-prepare')]
  #[CLI\Option(name: 'gap-id', description: 'UUID for this gap. Reuse it only for an identical retry.')]
  #[CLI\Option(name: 'fork-id', description: 'Live row id the lost branch diverged from.')]
  #[CLI\Option(name: 'fork-row-hash', description: 'row_hash of the fork row.')]
  #[CLI\Option(name: 'lost-from-id', description: 'First lost row id.')]
  #[CLI\Option(name: 'lost-through-id', description: 'Last lost row id.')]
  #[CLI\Option(name: 'lost-count', description: 'Number of lost rows.')]
  #[CLI\Option(name: 'lost-from-timestamp', description: 'Unix time of the first lost row.')]
  #[CLI\Option(name: 'lost-through-timestamp', description: 'Unix time of the last lost row.')]
  #[CLI\Option(name: 'lost-head-row-hash', description: 'row_hash of the lost branch head.')]
  #[CLI\Option(name: 'first-live-row-hash', description: 'row_hash of the first live row after the fork.')]
  #[CLI\Option(name: 'manifest-digest', description: 'SHA-256 of the archive manifest file.')]
  #[CLI\Option(name: 'rows-digest', description: 'SHA-256 of the archived branch NDJSON.')]
  #[CLI\Option(name: 'dump-digest', description: 'SHA-256 of the source dump file.')]
  public function prepare(
    array $options = [
      'gap-id' => '',
      'fork-id' => '',
      'fork-row-hash' => '',
      'lost-from-id' => '',
      'lost-through-id' => '',
      'lost-count' => '',
      'lost-from-timestamp' => '',
      'lost-through-timestamp' => '',
      'lost-head-row-hash' => '',
      'first-live-row-hash' => '',
      'manifest-digest' => '',
      'rows-digest' => '',
      'dump-digest' => '',
    ],
  ): int {
    $this->printJson($this->gaps->prepare($this->statement($options)));
    return self::EXIT_SUCCESS;
  }

  /**
   * Append one reviewed gap row.
   */
  #[CLI\Command(name: 'audit-chain:record-gap')]
  #[CLI\Option(name: 'gap-id', description: 'UUID for this gap. Reuse it only for an identical retry.')]
  #[CLI\Option(name: 'snapshot', description: 'Exact digest from gap-prepare.')]
  #[CLI\Option(name: 'fork-id', description: 'Live row id the lost branch diverged from.')]
  #[CLI\Option(name: 'fork-row-hash', description: 'row_hash of the fork row.')]
  #[CLI\Option(name: 'lost-from-id', description: 'First lost row id.')]
  #[CLI\Option(name: 'lost-through-id', description: 'Last lost row id.')]
  #[CLI\Option(name: 'lost-count', description: 'Number of lost rows.')]
  #[CLI\Option(name: 'lost-from-timestamp', description: 'Unix time of the first lost row.')]
  #[CLI\Option(name: 'lost-through-timestamp', description: 'Unix time of the last lost row.')]
  #[CLI\Option(name: 'lost-head-row-hash', description: 'row_hash of the lost branch head.')]
  #[CLI\Option(name: 'first-live-row-hash', description: 'row_hash of the first live row after the fork.')]
  #[CLI\Option(name: 'manifest-digest', description: 'SHA-256 of the archive manifest file.')]
  #[CLI\Option(name: 'rows-digest', description: 'SHA-256 of the archived branch NDJSON.')]
  #[CLI\Option(name: 'dump-digest', description: 'SHA-256 of the source dump file.')]
  public function record(
    array $options = [
      'gap-id' => '',
      'snapshot' => '',
      'fork-id' => '',
      'fork-row-hash' => '',
      'lost-from-id' => '',
      'lost-through-id' => '',
      'lost-count' => '',
      'lost-from-timestamp' => '',
      'lost-through-timestamp' => '',
      'lost-head-row-hash' => '',
      'first-live-row-hash' => '',
      'manifest-digest' => '',
      'rows-digest' => '',
      'dump-digest' => '',
    ],
  ): int {
    $this->logger()->warning('This records a known gap. No existing row is rewritten, and a second recovery segment is not created.');
    if (!Drush::affirmative() && !$this->io()->confirm('Record this reviewed gap?', FALSE)) {
      return self::EXIT_FAILURE;
    }
    $result = $this->gaps->record($this->statement($options), (string) $options['snapshot']);
    $this->printJson($result);
    return self::EXIT_SUCCESS;
  }

  /**
   * Check an archived branch file against a recorded gap.
   */
  #[CLI\Command(name: 'audit-chain:gap-check')]
  #[CLI\Option(name: 'row', description: 'Recorded gap row id.')]
  #[CLI\Option(name: 'archive', description: 'Archived branch NDJSON file.')]
  #[CLI\Option(name: 'manifest', description: 'Archive manifest file.')]
  #[CLI\Option(name: 'dump', description: 'Source dump file.')]
  public function check(
    array $options = [
      'row' => '',
      'archive' => '',
      'manifest' => '',
      'dump' => '',
    ],
  ): int {
    $row = $this->integerOption($options, 'row');
    $result = $this->gaps->checkArchive(
      $row,
      (string) $options['archive'],
      (string) $options['manifest'],
      (string) $options['dump'],
    );
    $this->printJson($result);
    return $result['ok'] ? self::EXIT_SUCCESS : self::EXIT_FAILURE;
  }

  /**
   * Builds the service statement from command options.
   *
   * @param array<string, mixed> $options
   *   Drush options.
   *
   * @return array<string, int|string>
   *   Canonical input fields.
   */
  private function statement(array $options): array {
    return [
      'gap_id' => (string) $options['gap-id'],
      'fork_id' => $this->integerOption($options, 'fork-id'),
      'fork_row_hash' => strtolower((string) $options['fork-row-hash']),
      'lost_from_id' => $this->integerOption($options, 'lost-from-id'),
      'lost_through_id' => $this->integerOption($options, 'lost-through-id'),
      'lost_count' => $this->integerOption($options, 'lost-count'),
      'lost_from_timestamp' => $this->integerOption($options, 'lost-from-timestamp'),
      'lost_through_timestamp' => $this->integerOption($options, 'lost-through-timestamp'),
      'lost_head_row_hash' => strtolower((string) $options['lost-head-row-hash']),
      'first_live_row_hash' => strtolower((string) $options['first-live-row-hash']),
      'manifest_digest' => strtolower((string) $options['manifest-digest']),
      'rows_digest' => strtolower((string) $options['rows-digest']),
      'dump_digest' => strtolower((string) $options['dump-digest']),
    ];
  }

  /**
   * Reads one integer option.
   *
   * @param array<string, mixed> $options
   *   Drush options.
   * @param string $name
   *   Option name.
   *
   * @return int
   *   The integer value.
   */
  private function integerOption(array $options, string $name): int {
    $value = $options[$name] ?? '';
    if (is_int($value)) {
      return $value;
    }
    $parsed = filter_var((string) $value, FILTER_VALIDATE_INT);
    if ($parsed === FALSE) {
      throw new \InvalidArgumentException('Option --' . $name . ' must be an integer.');
    }
    return $parsed;
  }

  /**
   * Writes one JSON result.
   *
   * @param array<string, mixed> $value
   *   Result to print.
   */
  private function printJson(array $value): void {
    $this->output()->writeln(json_encode($value, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
  }

}
