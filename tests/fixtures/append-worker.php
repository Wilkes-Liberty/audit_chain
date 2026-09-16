<?php

/**
 * @file
 * Independent-process append fixture using test connection options from stdin.
 */

declare(strict_types=1);

use Drupal\audit_chain\AuditChainLogger;
use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\ImmutableConfig;
use Drupal\Core\Database\Database;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Lock\DatabaseLockBackend;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\Core\State\StateInterface;
use Drupal\encrypt\EncryptServiceInterface;
use Drupal\key\Entity\Key;
use Drupal\key\KeyRepositoryInterface;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\HttpFoundation\RequestStack;

if (PHP_SAPI !== 'cli') {
  exit(1);
}

$loader = require $argv[1] . '/autoload.php';
require_once $argv[1] . '/core/includes/bootstrap.inc';
$loader->addPsr4('Drupal\\audit_chain\\', dirname(__DIR__, 2) . '/src');
foreach (['mysql', 'pgsql'] as $driver) {
  $loader->addPsr4('Drupal\\' . $driver . '\\', $argv[1] . '/core/modules/' . $driver . '/src');
}

$input = json_decode(stream_get_contents(STDIN), TRUE, 512, JSON_THROW_ON_ERROR);

foreach ($input['namespaces'] as $namespace => $path) {
  $loader->addPsr4($namespace, $path);
}

// Only test-prefixed tables are eligible. Never use an ordinary site schema.
if (!preg_match('/^test[0-9]+/', $input['database']['prefix'] ?? '')) {
  throw new RuntimeException('A kernel-test table prefix is required.');
}

$builder = new class('appendWorker') extends TestCase {

  /**
   * Builds a real logger with synthetic request and signing services.
   */
  public function build(array $options): AuditChainLogger {
    Database::addConnectionInfo('worker', 'default', $options);
    Database::addConnectionInfo('worker_lock', 'default', $options);
    $config = $this->createMock(ImmutableConfig::class);
    $config->method('get')->willReturnMap([
      ['hash_key', 'serialization_test'],
      ['encryption_profile', NULL],
      ['stream_enabled', FALSE],
    ]);
    $factory = $this->createMock(ConfigFactoryInterface::class);
    $factory->method('get')->willReturn($config);
    $key = $this->createMock(Key::class);
    $key->method('getKeyValue')->willReturn('synthetic-serialization-key');
    $keys = $this->createMock(KeyRepositoryInterface::class);
    $keys->method('getKey')->willReturn($key);
    $account = $this->createMock(AccountProxyInterface::class);
    $account->method('id')->willReturn(0);
    $time = $this->createMock(TimeInterface::class);
    $time->method('getRequestTime')->willReturn(1);
    return new AuditChainLogger(
      Database::getConnection('default', 'worker'),
      $account,
      new RequestStack(),
      $factory,
      $time,
      $keys,
      // A separate connection exposes the early external-lock-release defect.
      new DatabaseLockBackend(Database::getConnection('default', 'worker_lock')),
      new NullLogger(),
      $this->createMock(EncryptServiceInterface::class),
      $this->createMock(EntityTypeManagerInterface::class),
      $this->createMock(StateInterface::class),
    );
  }

};
$logger = $builder->build($input['database']);
$database = Database::getConnection('default', 'worker');
if ($database->driver() === 'mysql') {
  $database->query('SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ');
  $database->query('SET SESSION innodb_lock_wait_timeout = 8');
}
else {
  $database->query("SET lock_timeout = '8s'");
}
$transaction = $database->startTransaction();
// Establish a repeatable-read snapshot before acquiring append serialization.
$database->select('audit_chain_log', 'l')->fields('l', ['id'])->execute()->fetchAll();
if (isset($input['started'])) {
  file_put_contents($input['started'], 'started');
}
$logger->logKeyed('test', $input['operation']);
if (isset($input['ready'])) {
  file_put_contents($input['ready'], 'ready');
  $deadline = microtime(TRUE) + 20;
  while (!is_file($input['release'])) {
    if (microtime(TRUE) > $deadline) {
      $transaction->rollBack();
      throw new RuntimeException('Parent did not release the test transaction.');
    }
    usleep(20000);
  }
}
if ($input['rollback'] ?? FALSE) {
  $transaction->rollBack();
}
unset($transaction);
print "committed-or-rolled-back\n";
