<?php

declare(strict_types=1);

namespace Drupal\audit_chain;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Site\Settings;
use Drupal\Core\State\StateInterface;

/**
 * Walks a controlled demo site through both witness backends.
 *
 * The shipped witness_backend setting stays empty. This class runs only
 * when settings.php sets audit_chain_witness_demo to TRUE. It never signs
 * an XRPL transaction: submit still goes to the configured relay.
 */
final class WitnessDemo {

  /**
   * Backends the demo submits to, in this order.
   */
  public const BACKENDS = ['opentimestamps', 'xrpl'];

  /**
   * State key for the last demo digest and receipt ids.
   */
  private const STATE_KEY = 'audit_chain.witness_demo';

  public function __construct(
    private readonly Settings $settings,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly StateInterface $state,
    private readonly ArchiveBundleExporter $archives,
    private readonly WitnessManager $witnesses,
    private readonly RewindDetector $rewind,
    private readonly Connection $database,
  ) {}

  /**
   * Whether the demo switch is on.
   */
  public function enabled(): bool {
    return $this->settings->get('audit_chain_witness_demo') === TRUE;
  }

  /**
   * Runs one named demo step.
   *
   * @param string $step
   *   Prepare, checkpoint, submit, status, upgrade, verify, tamper, reset,
   *   or run.
   * @param string $digest
   *   Checkpoint digest. Empty uses the last digest stored by this demo.
   *
   * @return \Drupal\audit_chain\WitnessOperation
   *   Lines the command prints. A non-zero exit is a refused or failed step.
   */
  public function step(string $step, string $digest = ''): WitnessOperation {
    if ($step !== 'reset' && !$this->enabled()) {
      return new WitnessOperation(1, ['witness_demo_disabled']);
    }
    if ($step === 'prepare') {
      return $this->prepare();
    }
    if ($step === 'checkpoint') {
      return $this->checkpoint();
    }
    if ($step === 'submit') {
      return $this->submit($digest);
    }
    if ($step === 'status') {
      return $this->status($digest);
    }
    if ($step === 'upgrade') {
      return $this->upgrade($digest);
    }
    if ($step === 'verify') {
      return $this->verify($digest);
    }
    if ($step === 'tamper') {
      return $this->tamper($digest);
    }
    if ($step === 'reset') {
      return $this->reset();
    }
    if ($step === 'run') {
      return $this->run();
    }
    return new WitnessOperation(1, ['witness_demo_unknown_step']);
  }

  /**
   * Copies testnet relay settings into site config without enabling cron.
   *
   * The witness_backend setting stays empty so scheduled verification
   * does not start submitting. The relay token stays in settings.php.
   */
  private function prepare(): WitnessOperation {
    $relay = $this->settingString('audit_chain_witness_xrpl_relay_url');
    $read = $this->settingString('audit_chain_witness_xrpl_read_url');
    $account = $this->settingString('audit_chain_witness_xrpl_witness_account');
    $sink = $this->settingString('audit_chain_witness_xrpl_sink_address');
    $token = $this->settingString('audit_chain_witness_xrpl_token');
    $missing = [];
    foreach ([
      'audit_chain_witness_xrpl_relay_url' => $relay,
      'audit_chain_witness_xrpl_read_url' => $read,
      'audit_chain_witness_xrpl_witness_account' => $account,
      'audit_chain_witness_xrpl_sink_address' => $sink,
      'audit_chain_witness_xrpl_token' => $token,
    ] as $key => $value) {
      if ($value === '') {
        $missing[] = $key;
      }
    }
    if ($missing !== []) {
      return new WitnessOperation(1, array_merge(['witness_demo_unconfigured'], $missing));
    }
    $urls = $relay . ' ' . $read;
    if (preg_match('/mainnet|s[12]\.ripple\.com|xrplcluster/i', $urls) === 1) {
      return new WitnessOperation(1, ['witness_xrpl_mainnet_refused']);
    }
    $editable = $this->configFactory->getEditable('audit_chain.settings');
    // Leave the shipped selector off. Demo steps name both backends.
    $editable->set('witness_xrpl', [
      'relay_url' => $relay,
      'read_url' => $read,
      'network' => 'xrpl:testnet',
      'sink_address' => $sink,
      'witness_account' => $account,
    ])->save();
    $ots = $editable->get('witness_opentimestamps');
    $calendars = is_array($ots) && isset($ots['calendars']) && is_array($ots['calendars'])
      ? $ots['calendars']
      : [];
    return new WitnessOperation(0, [
      'demo=on',
      'witness_backend=' . (string) $editable->get('witness_backend'),
      'xrpl_network=xrpl:testnet',
      'xrpl_relay=' . $relay,
      'xrpl_read=' . $read,
      'ots_calendars=' . implode(',', $calendars),
    ]);
  }

  /**
   * Closes one archive checkpoint over the live chain.
   */
  private function checkpoint(): WitnessOperation {
    try {
      $bundle = $this->archives->create();
    }
    catch (\Throwable $exception) {
      return new WitnessOperation(1, [$exception->getMessage()]);
    }
    $digest = (string) $bundle['manifest']['digest'];
    $this->storeSession($digest, []);
    return new WitnessOperation(0, [
      'digest=' . $digest,
      'from_id=' . (int) $bundle['manifest']['window']['from_id'],
      'through_id=' . (int) $bundle['manifest']['window']['through_id'],
    ]);
  }

  /**
   * Submits the checkpoint to both backends.
   *
   * A calendar or relay failure on one backend does not roll back the other.
   */
  private function submit(string $digest): WitnessOperation {
    $resolved = $this->digest($digest);
    if ($resolved === NULL) {
      return new WitnessOperation(1, ['witness_demo_digest_required']);
    }
    $results = $this->witnesses->submitTo($resolved, self::BACKENDS);
    $lines = ['digest=' . $resolved];
    $ids = [];
    $failed = FALSE;
    foreach ($results as $result) {
      $receipt = $result['receipt'];
      if ($receipt instanceof WitnessReceipt) {
        $ids[] = $receipt->id;
        $lines[] = $receipt->id . ' ' . $receipt->backendId . ' ' . $receipt->status;
      }
      else {
        $failed = TRUE;
        $lines[] = $result['backend_id'] . ' ' . (string) $result['error'];
      }
    }
    $this->storeSession($resolved, $ids);
    return new WitnessOperation($failed ? 1 : 0, $lines);
  }

  /**
   * Prints stored receipts without requiring a confirmed witness.
   */
  private function status(string $digest): WitnessOperation {
    $resolved = $this->digest($digest);
    if ($resolved === NULL) {
      return new WitnessOperation(1, ['witness_demo_digest_required']);
    }
    $lines = ['digest=' . $resolved];
    foreach ($this->witnesses->recordsForDigest($resolved) as $record) {
      $lines[] = $record['id'] . ' ' . $record['backend_id'] . ' ' . $record['status'];
    }
    return new WitnessOperation(0, $lines);
  }

  /**
   * Advances each stored receipt one step.
   *
   * OpenTimestamps stays pending until a calendar returns a Bitcoin
   * attestation. That often takes hours. A still-pending upgrade is success.
   */
  private function upgrade(string $digest): WitnessOperation {
    $resolved = $this->digest($digest);
    if ($resolved === NULL) {
      return new WitnessOperation(1, ['witness_demo_digest_required']);
    }
    $lines = ['digest=' . $resolved];
    $failed = FALSE;
    foreach ($this->witnesses->recordsForDigest($resolved) as $record) {
      try {
        $receipt = $this->witnesses->upgrade($record['id']);
        $lines[] = $receipt->id . ' ' . $receipt->backendId . ' ' . $receipt->status;
      }
      catch (\Throwable $exception) {
        $failed = TRUE;
        $lines[] = $record['id'] . ' ' . $record['backend_id'] . ' ' . $exception->getMessage();
      }
    }
    return new WitnessOperation($failed ? 1 : 0, $lines);
  }

  /**
   * Fresh-verifies each stored receipt against the checkpoint digest.
   */
  private function verify(string $digest): WitnessOperation {
    $resolved = $this->digest($digest);
    if ($resolved === NULL) {
      return new WitnessOperation(1, ['witness_demo_digest_required']);
    }
    $lines = ['digest=' . $resolved];
    $failed = FALSE;
    foreach ($this->witnesses->recordsForDigest($resolved) as $record) {
      $verdict = $this->witnesses->verify($record['id'], $resolved);
      $state = $verdict->valid ? 'valid' : 'invalid';
      $lines[] = $record['id'] . ' ' . $record['backend_id'] . ' ' . $record['status'] . ' ' . $state . ' ' . $verdict->reason;
      if (!$verdict->valid && $record['status'] === WitnessReceipt::STATUS_CONFIRMED) {
        $failed = TRUE;
      }
    }
    return new WitnessOperation($failed ? 1 : 0, $lines);
  }

  /**
   * Shows fail-closed verify and the existing rewind detector.
   *
   * The chain is not modified. A still-pending OpenTimestamps receipt is
   * expected. Rewind uses assessBackend() so the shipped empty selector
   * stays off.
   */
  private function tamper(string $digest): WitnessOperation {
    $resolved = $this->digest($digest);
    if ($resolved === NULL) {
      return new WitnessOperation(1, ['witness_demo_digest_required']);
    }
    $tampered = $this->flipDigest($resolved);
    $lines = [
      'digest=' . $resolved,
      'tampered=' . $tampered,
    ];
    $sawInvalid = FALSE;
    foreach ($this->witnesses->recordsForDigest($resolved) as $record) {
      $verdict = $this->witnesses->verify($record['id'], $tampered);
      $lines[] = $record['id'] . ' ' . $record['backend_id'] . ' tamper ' . ($verdict->valid ? 'valid' : 'invalid') . ' ' . $verdict->reason;
      if (!$verdict->valid) {
        $sawInvalid = TRUE;
      }
    }
    $scheduled = $this->rewind->assess();
    $lines[] = 'rewind_scheduled ' . $scheduled['status'] . ' ' . $scheduled['reason'];
    foreach (self::BACKENDS as $backend) {
      $assessment = $this->rewind->assessBackend($backend);
      $lines[] = 'rewind_' . $backend . ' ' . $assessment['status'] . ' ' . $assessment['reason'];
    }
    return new WitnessOperation($sawInvalid ? 0 : 1, $lines);
  }

  /**
   * Restores empty XRPL site config and removes receipts this demo stored.
   *
   * Audit-chain rows and checkpoints stay. witness_backend is left as it
   * was: prepare never writes it.
   */
  private function reset(): WitnessOperation {
    $session = $this->session();
    $removed = 0;
    if ($session['digest'] !== '') {
      $removed = (int) $this->database->delete('audit_chain_witness_receipt')
        ->condition('checkpoint_digest', $session['digest'])
        ->execute();
    }
    $this->configFactory->getEditable('audit_chain.settings')->set('witness_xrpl', [
      'relay_url' => '',
      'read_url' => '',
      'network' => '',
      'sink_address' => '',
      'witness_account' => '',
    ])->save();
    $this->state->delete(self::STATE_KEY);
    $backend = $this->configFactory->get('audit_chain.settings')->get('witness_backend');
    return new WitnessOperation(0, [
      'removed=' . $removed,
      'witness_backend=' . (is_string($backend) ? $backend : ''),
      'xrpl_relay=',
    ]);
  }

  /**
   * Walks prepare through tamper. Reset stays a separate command.
   */
  private function run(): WitnessOperation {
    $lines = [];
    $exit = 0;
    foreach (['prepare', 'checkpoint', 'submit', 'status', 'upgrade', 'verify', 'tamper'] as $step) {
      $result = $this->step($step);
      $lines[] = 'step=' . $step . ' exit=' . $result->exitCode;
      foreach ($result->lines as $line) {
        $lines[] = $line;
      }
      if ($result->exitCode !== 0) {
        $exit = $result->exitCode;
        break;
      }
    }
    return new WitnessOperation($exit, $lines);
  }

  /**
   * Resolves the digest for a step.
   */
  private function digest(string $digest): ?string {
    if (preg_match('/^[a-f0-9]{64}$/D', $digest) === 1) {
      return $digest;
    }
    $stored = $this->session()['digest'];
    return $stored === '' ? NULL : $stored;
  }

  /**
   * Reads one settings string and trims it.
   */
  private function settingString(string $key): string {
    $value = $this->settings->get($key, '');
    return is_string($value) ? trim($value) : '';
  }

  /**
   * Remembers the digest the demo is walking.
   *
   * @param string $digest
   *   Checkpoint digest.
   * @param list<string> $receiptIds
   *   Receipt ids from the last submit, when known.
   */
  private function storeSession(string $digest, array $receiptIds): void {
    $this->state->set(self::STATE_KEY, [
      'digest' => $digest,
      'receipt_ids' => $receiptIds,
    ]);
  }

  /**
   * Loads the last demo session.
   *
   * @return array{digest: string, receipt_ids: list<string>}
   *   Empty strings when the demo has not stored a digest.
   */
  private function session(): array {
    $value = $this->state->get(self::STATE_KEY);
    if (!is_array($value) || !isset($value['digest']) || !is_string($value['digest'])) {
      return ['digest' => '', 'receipt_ids' => []];
    }
    $ids = [];
    if (isset($value['receipt_ids']) && is_array($value['receipt_ids'])) {
      foreach ($value['receipt_ids'] as $id) {
        if (is_string($id) && $id !== '') {
          $ids[] = $id;
        }
      }
    }
    return [
      'digest' => $value['digest'],
      'receipt_ids' => $ids,
    ];
  }

  /**
   * Flips the first hex nibble so verify sees a different digest.
   */
  private function flipDigest(string $digest): string {
    $nibble = $digest[0] === '0' ? '1' : '0';
    return $nibble . substr($digest, 1);
  }

}
