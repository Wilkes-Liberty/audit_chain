<?php

declare(strict_types=1);

namespace Drupal\audit_chain;

use Drupal\audit_chain\Witness\DestinationPolicy;
use Drupal\audit_chain\Witness\WitnessDnsResolverInterface;
use Drupal\audit_chain\Witness\WitnessTransportInterface;
use Drupal\Component\Uuid\UuidInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Site\Settings;

/**
 * Records an XRPL witness receipt without holding a seed.
 *
 * The relay receives the digest and a durable request id. This client never
 * signs, and it confirms only after a separate read shows a validated
 * tesSUCCESS payment of the fixed one-drop template. Mainnet URLs are refused.
 */
final class XrplWitnessBackend implements IdentifiedWitnessBackendInterface {

  private const CONTRACT = 'audit_chain.checkpoint.v1';

  private const MEMO_TYPE_TEXT = 'audit_chain.checkpoint.v1';

  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly WitnessTransportInterface $transport,
    private readonly WitnessDnsResolverInterface $dns,
    private readonly UuidInterface $uuid,
    private readonly Settings $settings,
  ) {}

  /**
   * {@inheritdoc}
   */
  public function id(): string {
    return 'xrpl';
  }

  /**
   * Builds a pending receipt before any relay request.
   */
  public function reserve(string $digestHex): WitnessReceipt {
    $digest = $this->rawDigest($digestHex);
    $config = $this->configuration();
    $requestId = $this->uuid->generate();
    return new WitnessReceipt(
      $this->uuid->generate(),
      $this->id(),
      WitnessReceipt::STATUS_PENDING,
      $this->encodeToken($this->tokenData($config, $requestId, NULL, 'pending', $digest)),
    );
  }

  /**
   * Submits the reserved request id and interprets the relay response.
   */
  public function dispatch(WitnessReceipt $reserved): WitnessReceipt {
    $token = $this->decodeToken($reserved->opaqueToken);
    $config = $this->configuration();
    $this->assertTemplate($token, $config);
    $response = $this->postRelay($config, (string) $token['request_id'], (string) $token['template']['memo_data']);
    return $this->applyRelay($reserved, $token, $config, $response);
  }

  /**
   * Keeps the same request id when the relay outcome is unknown.
   */
  public function uncertain(WitnessReceipt $reserved): WitnessReceipt {
    $token = $this->decodeToken($reserved->opaqueToken);
    $token['outcome'] = 'uncertain';
    return new WitnessReceipt(
      $reserved->id,
      $reserved->backendId,
      WitnessReceipt::STATUS_PENDING,
      $this->encodeToken($token),
    );
  }

  /**
   * {@inheritdoc}
   */
  public function submit(string $digestHex, array $context): WitnessReceipt {
    if ($context !== ['contract' => self::CONTRACT]) {
      throw new \RuntimeException('witness_context_rejected');
    }
    $reserved = $this->reserve($digestHex);
    return $this->dispatch($reserved);
  }

  /**
   * {@inheritdoc}
   */
  public function upgrade(WitnessReceipt $pending): WitnessReceipt {
    $this->assertBackend($pending);
    $token = $this->decodeToken($pending->opaqueToken);
    if ($pending->status === WitnessReceipt::STATUS_CONFIRMED && $token['outcome'] === 'confirmed' && is_string($token['tx_hash'])) {
      return $pending;
    }
    $config = $this->configuration();
    $this->assertTemplate($token, $config);
    if (is_string($token['tx_hash'])) {
      $read = $this->readTransaction($config, $token['tx_hash'], $token);
      if ($read['state'] === 'confirmed') {
        $token['outcome'] = 'confirmed';
        return new WitnessReceipt(
          $pending->id,
          $pending->backendId,
          WitnessReceipt::STATUS_CONFIRMED,
          $this->encodeToken($token),
        );
      }
      if ($read['state'] === 'unavailable') {
        throw new \RuntimeException('backend_unreachable');
      }
    }
    try {
      $response = $this->postRelay($config, (string) $token['request_id'], (string) $token['template']['memo_data']);
    }
    catch (\RuntimeException) {
      throw new \RuntimeException('backend_unreachable');
    }
    return $this->applyRelay($pending, $token, $config, $response);
  }

  /**
   * {@inheritdoc}
   */
  public function verify(WitnessReceipt $receipt, string $digestHex): WitnessVerdict {
    $this->assertBackend($receipt);
    try {
      $token = $this->decodeToken($receipt->opaqueToken);
      $config = $this->configuration();
      $this->assertTemplate($token, $config);
    }
    catch (\RuntimeException) {
      return new WitnessVerdict(FALSE, 'receipt_malformed');
    }
    $expected = bin2hex($this->rawDigest($digestHex));
    if (!hash_equals($expected, strtolower((string) $token['template']['memo_data']))) {
      return new WitnessVerdict(FALSE, 'attestation_mismatch');
    }
    if (!is_string($token['tx_hash'])) {
      return new WitnessVerdict(FALSE, 'receipt_not_final', [
        'outcome' => (string) $token['outcome'],
        'request_id' => (string) $token['request_id'],
        'trust_mode' => 'relay_and_read_url',
      ]);
    }
    $read = $this->readTransaction($config, $token['tx_hash'], $token);
    if ($read['state'] === 'confirmed') {
      return new WitnessVerdict(TRUE, 'confirmed', $read['evidence']);
    }
    if ($read['state'] === 'unavailable') {
      return new WitnessVerdict(FALSE, 'backend_unreachable', $read['evidence']);
    }
    if ($read['state'] === 'not_final') {
      return new WitnessVerdict(FALSE, 'receipt_not_final', $read['evidence']);
    }
    return new WitnessVerdict(FALSE, 'attestation_mismatch', $read['evidence']);
  }

  /**
   * Lists confirmed checkpoint digests from the ledger read service.
   *
   * Local receipt rows are not consulted. A database restore removes those
   * rows and leaves this list in place. Non-witness payments are ignored.
   *
   * @return list<array{digest: string, ledger_index: int}>
   *   Confirmed digests. Order is the read service's order.
   *
   * @throws \RuntimeException
   *   When the list cannot be read. An empty list is a successful read.
   */
  public function confirmedDigests(): array {
    $config = $this->configuration();
    $url = rtrim($config['read_url'], '/') . '/accounts/' . $config['witness_account'] . '/transactions';
    try {
      $policy = new DestinationPolicy($this->dns);
      $policy->assertAllowed($url, [DestinationPolicy::host($config['read_url'])]);
      $result = $this->transport->request('GET', $url, '', [
        'Accept' => 'application/json',
        'User-Agent' => 'audit_chain',
      ], 2000000);
    }
    catch (\RuntimeException) {
      throw new \RuntimeException('backend_unreachable');
    }
    if ($result['status'] !== 200) {
      throw new \RuntimeException('backend_unreachable');
    }
    $decoded = json_decode($result['body'], TRUE);
    if (!is_array($decoded) || array_keys($decoded) !== ['transactions'] || !is_array($decoded['transactions'])) {
      throw new \RuntimeException('backend_unreachable');
    }
    $found = [];
    foreach ($decoded['transactions'] as $tx) {
      if (!is_array($tx) || !$this->isWitnessPayment($tx, $config)) {
        continue;
      }
      $index = $tx['ledger_index'] ?? NULL;
      if (!is_int($index) || $index < 1) {
        continue;
      }
      $memo = $tx['Memos'][0]['Memo'];
      $found[] = [
        'digest' => strtolower((string) $memo['MemoData']),
        'ledger_index' => $index,
      ];
    }
    return $found;
  }

  /**
   * Applies one relay response without treating it as confirmation.
   *
   * @param \Drupal\audit_chain\WitnessReceipt $receipt
   *   Reserved receipt.
   * @param array<string, mixed> $token
   *   Stored witness token.
   * @param array<string, string> $config
   *   XRPL witness settings.
   * @param array<string, mixed> $response
   *   Relay JSON body.
   *
   * @return \Drupal\audit_chain\WitnessReceipt
   *   Pending until a separate read confirms the transaction.
   */
  private function applyRelay(WitnessReceipt $receipt, array $token, array $config, array $response): WitnessReceipt {
    $outcome = $response['outcome'] ?? '';
    if ($outcome === 'invalid') {
      $token['outcome'] = 'invalid';
      return new WitnessReceipt($receipt->id, $receipt->backendId, WitnessReceipt::STATUS_PENDING, $this->encodeToken($token));
    }
    $hash = $response['tx_hash'] ?? NULL;
    if ($hash !== NULL && $this->validHash($hash) === FALSE) {
      $token['outcome'] = 'invalid';
      return new WitnessReceipt($receipt->id, $receipt->backendId, WitnessReceipt::STATUS_PENDING, $this->encodeToken($token));
    }
    if (is_string($token['tx_hash']) && is_string($hash) && !hash_equals($token['tx_hash'], $hash)) {
      $token['outcome'] = 'invalid';
      return new WitnessReceipt($receipt->id, $receipt->backendId, WitnessReceipt::STATUS_PENDING, $this->encodeToken($token));
    }
    if (is_string($hash) && !is_string($token['tx_hash'])) {
      $token['tx_hash'] = $hash;
    }
    if ($outcome === 'uncertain' || $outcome === 'pending' || $outcome === '') {
      $token['outcome'] = $outcome === 'uncertain' ? 'uncertain' : 'pending';
      return new WitnessReceipt($receipt->id, $receipt->backendId, WitnessReceipt::STATUS_PENDING, $this->encodeToken($token));
    }
    if ($outcome !== 'confirmed' || !is_string($token['tx_hash'])) {
      $token['outcome'] = 'uncertain';
      return new WitnessReceipt($receipt->id, $receipt->backendId, WitnessReceipt::STATUS_PENDING, $this->encodeToken($token));
    }
    $read = $this->readTransaction($config, $token['tx_hash'], $token);
    if ($read['state'] === 'confirmed') {
      $token['outcome'] = 'confirmed';
      return new WitnessReceipt($receipt->id, $receipt->backendId, WitnessReceipt::STATUS_CONFIRMED, $this->encodeToken($token));
    }
    $token['outcome'] = $read['state'] === 'invalid' ? 'invalid' : 'uncertain';
    return new WitnessReceipt($receipt->id, $receipt->backendId, WitnessReceipt::STATUS_PENDING, $this->encodeToken($token));
  }

  /**
   * Posts the digest and request id to the witness relay.
   *
   * @param array<string, string> $config
   *   XRPL witness settings.
   * @param string $requestId
   *   Durable submission id.
   * @param string $memoData
   *   Hex digest used only to rebuild the raw digest locally.
   *
   * @return array<string, mixed>
   *   Relay JSON. It is not a confirmation.
   */
  private function postRelay(array $config, string $requestId, string $memoData): array {
    $digestHex = bin2hex((string) hex2bin($memoData));
    $body = '{"digest":"' . $digestHex . '","request_id":"' . $requestId . '"}';
    $policy = new DestinationPolicy($this->dns);
    $policy->assertAllowed($config['relay_url'], [DestinationPolicy::host($config['relay_url'])]);
    $result = $this->transport->request('POST', $config['relay_url'], $body, [
      'Accept' => 'application/json',
      'Content-Type' => 'application/json',
      'Authorization' => 'Bearer ' . $this->token(),
      'User-Agent' => 'audit_chain',
    ], 65536);
    if ($result['status'] >= 500 || ($result['status'] >= 300 && $result['status'] < 400)) {
      throw new \RuntimeException('backend_unreachable');
    }
    $decoded = json_decode($result['body'], TRUE);
    if ($result['status'] !== 200 || !is_array($decoded)) {
      throw new \RuntimeException('backend_unreachable');
    }
    return $decoded;
  }

  /**
   * Reads one transaction from the configured ledger endpoint.
   *
   * @param array<string, string> $config
   *   XRPL witness settings.
   * @param string $hash
   *   Transaction hash to read.
   * @param array<string, mixed> $token
   *   Stored witness token used to check the template.
   *
   * @return array{state: string, evidence: array<string, int|string>}
   *   confirmed, not_final, invalid, or unavailable.
   */
  private function readTransaction(array $config, string $hash, array $token): array {
    $url = rtrim($config['read_url'], '/') . '/transactions/' . $hash;
    $evidence = [
      'tx_hash' => $hash,
      'request_id' => (string) $token['request_id'],
      'trust_mode' => 'relay_and_read_url',
    ];
    try {
      $policy = new DestinationPolicy($this->dns);
      $policy->assertAllowed($url, [DestinationPolicy::host($config['read_url'])]);
      $result = $this->transport->request('GET', $url, '', [
        'Accept' => 'application/json',
        'User-Agent' => 'audit_chain',
      ], 65536);
    }
    catch (\RuntimeException) {
      return ['state' => 'unavailable', 'evidence' => $evidence];
    }
    if ($result['status'] >= 500 || ($result['status'] >= 300 && $result['status'] < 400)) {
      return ['state' => 'unavailable', 'evidence' => $evidence];
    }
    $tx = json_decode($result['body'], TRUE);
    if ($result['status'] !== 200 || !is_array($tx)) {
      return ['state' => 'invalid', 'evidence' => $evidence];
    }
    $validated = $tx['validated'] ?? NULL;
    $meta = is_array($tx['meta'] ?? NULL) ? $tx['meta'] : [];
    $resultCode = $meta['TransactionResult'] ?? '';
    if ($validated !== TRUE) {
      return ['state' => 'not_final', 'evidence' => $evidence];
    }
    if ($resultCode !== 'tesSUCCESS' || !$this->transactionMatches($tx, $token)) {
      return ['state' => 'invalid', 'evidence' => $evidence];
    }
    $evidence['ledger_index'] = (int) ($tx['ledger_index'] ?? 0);
    $evidence['close_time'] = (int) ($tx['close_time'] ?? 0);
    $evidence['network'] = (string) $token['network'];
    return ['state' => 'confirmed', 'evidence' => $evidence];
  }

  /**
   * Whether a ledger transaction is the fixed one-drop witness payment.
   *
   * @param array<string, mixed> $tx
   *   Transaction object from the read endpoint.
   * @param array<string, string> $config
   *   XRPL witness settings.
   *
   * @return bool
   *   TRUE when the transaction is validated, successful, and the template.
   */
  private function isWitnessPayment(array $tx, array $config): bool {
    $meta = is_array($tx['meta'] ?? NULL) ? $tx['meta'] : [];
    if (($tx['validated'] ?? NULL) !== TRUE || ($meta['TransactionResult'] ?? '') !== 'tesSUCCESS') {
      return FALSE;
    }
    if (($tx['TransactionType'] ?? '') !== 'Payment') {
      return FALSE;
    }
    if (($tx['Account'] ?? '') !== $config['witness_account'] || ($tx['Destination'] ?? '') !== $config['sink_address']) {
      return FALSE;
    }
    if ((string) ($tx['Amount'] ?? '') !== '1' || (string) ($tx['Fee'] ?? '') !== '12') {
      return FALSE;
    }
    if (isset($tx['DestinationTag']) || isset($tx['Paths']) || isset($tx['SendMax'])) {
      return FALSE;
    }
    $memos = $tx['Memos'] ?? NULL;
    if (!is_array($memos) || count($memos) !== 1 || !is_array($memos[0]['Memo'] ?? NULL)) {
      return FALSE;
    }
    $memo = $memos[0]['Memo'];
    $type = strtolower((string) ($memo['MemoType'] ?? ''));
    $data = strtolower((string) ($memo['MemoData'] ?? ''));
    return hash_equals(bin2hex(self::MEMO_TYPE_TEXT), $type)
      && preg_match('/^[a-f0-9]{64}$/D', $data) === 1;
  }

  /**
   * Whether a ledger transaction is the fixed one-drop witness template.
   *
   * @param array<string, mixed> $tx
   *   Transaction object from the read endpoint.
   * @param array<string, mixed> $token
   *   Stored witness token.
   *
   * @return bool
   *   TRUE when type, accounts, amount, fee, and the one memo match.
   */
  private function transactionMatches(array $tx, array $token): bool {
    $template = $token['template'];
    if (!is_array($template)) {
      return FALSE;
    }
    if (($tx['TransactionType'] ?? '') !== 'Payment') {
      return FALSE;
    }
    if (($tx['Account'] ?? '') !== $template['account'] || ($tx['Destination'] ?? '') !== $template['destination']) {
      return FALSE;
    }
    if ((string) ($tx['Amount'] ?? '') !== '1' || (string) ($tx['Fee'] ?? '') !== '12') {
      return FALSE;
    }
    if (isset($tx['DestinationTag']) || isset($tx['Paths']) || isset($tx['SendMax'])) {
      return FALSE;
    }
    $memos = $tx['Memos'] ?? NULL;
    if (!is_array($memos) || count($memos) !== 1 || !is_array($memos[0]['Memo'] ?? NULL)) {
      return FALSE;
    }
    $memo = $memos[0]['Memo'];
    return hash_equals(strtolower((string) $template['memo_type']), strtolower((string) ($memo['MemoType'] ?? '')))
      && hash_equals(strtolower((string) $template['memo_data']), strtolower((string) ($memo['MemoData'] ?? '')));
  }

  /**
   * Builds the fixed-key witness token.
   *
   * @param array<string, string> $config
   *   XRPL witness settings.
   * @param string $requestId
   *   Durable submission id.
   * @param string|null $hash
   *   Transaction hash, or NULL before one is known.
   * @param string $outcome
   *   Pending, confirmed, uncertain, or invalid.
   * @param string $digest
   *   Raw 32-byte checkpoint digest.
   *
   * @return array<string, mixed>
   *   Token fields in the required order.
   */
  private function tokenData(array $config, string $requestId, ?string $hash, string $outcome, string $digest): array {
    return [
      'v' => 1,
      'network' => $config['network'],
      'request_id' => $requestId,
      'tx_hash' => $hash,
      'template' => [
        'transaction_type' => 'Payment',
        'account' => $config['witness_account'],
        'destination' => $config['sink_address'],
        'amount_drops' => '1',
        'fee_drops' => '12',
        'memo_type' => bin2hex(self::MEMO_TYPE_TEXT),
        'memo_data' => bin2hex($digest),
      ],
      'outcome' => $outcome,
    ];
  }

  /**
   * Rejects a token whose template is not the fixed witness payment.
   *
   * @param array<string, mixed> $token
   *   Stored witness token.
   * @param array<string, string> $config
   *   XRPL witness settings.
   */
  private function assertTemplate(array $token, array $config): void {
    $template = $token['template'] ?? NULL;
    if (!is_array($template)) {
      throw new \RuntimeException('receipt_malformed');
    }
    $expected = ['transaction_type', 'account', 'destination', 'amount_drops', 'fee_drops', 'memo_type', 'memo_data'];
    if (array_keys($template) !== $expected) {
      throw new \RuntimeException('receipt_malformed');
    }
    if ($template['transaction_type'] !== 'Payment' || $template['amount_drops'] !== '1' || $template['fee_drops'] !== '12') {
      throw new \RuntimeException('receipt_malformed');
    }
    if ($template['account'] !== $config['witness_account'] || $template['destination'] !== $config['sink_address']) {
      throw new \RuntimeException('receipt_malformed');
    }
    if ($token['network'] !== $config['network']) {
      throw new \RuntimeException('receipt_malformed');
    }
  }

  /**
   * Decodes a witness token and rejects extra or reordered keys.
   *
   * @param string $json
   *   Stored opaque token.
   *
   * @return array<string, mixed>
   *   Token fields in the required order.
   */
  private function decodeToken(string $json): array {
    $token = json_decode($json, TRUE);
    if (!is_array($token)) {
      throw new \RuntimeException('receipt_malformed');
    }
    $expected = ['v', 'network', 'request_id', 'tx_hash', 'template', 'outcome'];
    if (array_keys($token) !== $expected || $token['v'] !== 1) {
      throw new \RuntimeException('receipt_malformed');
    }
    if (!is_string($token['request_id']) || preg_match('/^[0-9a-f-]{36}$/D', $token['request_id']) !== 1) {
      throw new \RuntimeException('receipt_malformed');
    }
    if (!in_array($token['outcome'], ['pending', 'confirmed', 'uncertain', 'invalid'], TRUE)) {
      throw new \RuntimeException('receipt_malformed');
    }
    if ($token['tx_hash'] !== NULL && !$this->validHash($token['tx_hash'])) {
      throw new \RuntimeException('receipt_malformed');
    }
    return $token;
  }

  /**
   * Encodes a witness token.
   *
   * @param array<string, mixed> $token
   *   Token fields in the required order.
   *
   * @return string
   *   JSON stored in the receipt.
   */
  private function encodeToken(array $token): string {
    $json = json_encode($token, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    if (strlen($json) > 65000) {
      throw new \RuntimeException('receipt_malformed');
    }
    return $json;
  }

  /**
   * Loads XRPL witness settings and refuses mainnet.
   *
   * @return array{relay_url: string, read_url: string, network: string, sink_address: string, witness_account: string}
   *   Relay, read URL, network, and the two distinct accounts.
   */
  private function configuration(): array {
    $value = $this->configFactory->get('audit_chain.settings')->get('witness_xrpl');
    if (!is_array($value)) {
      throw new \RuntimeException('witness_xrpl_unconfigured');
    }
    foreach (['relay_url', 'read_url', 'network', 'sink_address', 'witness_account'] as $key) {
      if (!isset($value[$key]) || !is_string($value[$key]) || $value[$key] === '') {
        throw new \RuntimeException('witness_xrpl_unconfigured');
      }
    }
    $network = $value['network'];
    if ($network !== 'xrpl:testnet' && $network !== 'xrpl:devnet') {
      throw new \RuntimeException('witness_xrpl_mainnet_refused');
    }
    $urls = $value['relay_url'] . ' ' . $value['read_url'];
    if (preg_match('/mainnet|s[12]\.ripple\.com|xrplcluster/i', $urls) === 1) {
      throw new \RuntimeException('witness_xrpl_mainnet_refused');
    }
    if (!$this->validAccount($value['witness_account']) || !$this->validAccount($value['sink_address'])) {
      throw new \RuntimeException('witness_xrpl_unconfigured');
    }
    if ($value['witness_account'] === $value['sink_address']) {
      throw new \RuntimeException('witness_xrpl_unconfigured');
    }
    $this->token();
    return [
      'relay_url' => $value['relay_url'],
      'read_url' => $value['read_url'],
      'network' => $network,
      'sink_address' => $value['sink_address'],
      'witness_account' => $value['witness_account'],
    ];
  }

  /**
   * Reads the relay credential from settings and never from config.
   *
   * @return string
   *   Bearer token. A missing value fails before any request.
   */
  private function token(): string {
    $token = $this->settings->get('audit_chain_witness_xrpl_token', '');
    if (!is_string($token) || trim($token) === '') {
      throw new \RuntimeException('witness_xrpl_unconfigured');
    }
    return trim($token);
  }

  /**
   * Whether a value is a classic XRPL account address.
   *
   * @param string $account
   *   Account or sink address.
   *
   * @return bool
   *   TRUE when the address matches the classic form.
   */
  private function validAccount(string $account): bool {
    return preg_match('/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/D', $account) === 1;
  }

  /**
   * Whether a value is an uppercase XRPL transaction hash.
   *
   * @param mixed $hash
   *   Candidate hash.
   *
   * @return bool
   *   TRUE for 64 uppercase hex characters.
   */
  private function validHash(mixed $hash): bool {
    return is_string($hash) && preg_match('/^[A-F0-9]{64}$/D', $hash) === 1;
  }

  /**
   * Converts a lowercase hex digest to 32 raw bytes.
   *
   * @param string $digestHex
   *   Persisted checkpoint digest.
   *
   * @return string
   *   Raw digest bytes.
   */
  private function rawDigest(string $digestHex): string {
    if (preg_match('/^[a-f0-9]{64}$/D', $digestHex) !== 1) {
      throw new \InvalidArgumentException('A lowercase SHA-256 checkpoint digest is required.');
    }
    $raw = hex2bin($digestHex);
    if ($raw === FALSE) {
      throw new \InvalidArgumentException('A lowercase SHA-256 checkpoint digest is required.');
    }
    return $raw;
  }

  /**
   * Rejects a receipt that belongs to another backend.
   *
   * @param \Drupal\audit_chain\WitnessReceipt $receipt
   *   Receipt being upgraded or verified.
   */
  private function assertBackend(WitnessReceipt $receipt): void {
    if ($receipt->backendId !== $this->id()) {
      throw new \RuntimeException('witness_backend_mismatch');
    }
  }

}
