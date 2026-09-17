<?php

/**
 * @file
 * Independent-process append fixture using test connection options from stdin.
 */

declare(strict_types=1);

use Drupal\audit_chain\AuditChainLogger;
use Drupal\audit_chain\RecoverySegments;
use Drupal\Component\Datetime\TimeInterface;
use Drupal\Component\Datetime\Time;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\ImmutableConfig;
use Drupal\Core\Database\Database;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\Core\State\StateInterface;
use Drupal\Core\Site\Settings;
use Drupal\encrypt\EncryptServiceInterface;
use Drupal\key\Entity\Key;
use Drupal\key\KeyRepositoryInterface;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\HttpFoundation\RequestStack;

if (PHP_SAPI !== 'cli') {
  exit(1);
}

$drupalRoot = $argv[1];
$vendorDir = $argv[2] ?? '';
$autoload = NULL;
foreach ([
  $vendorDir . '/autoload.php',
  $drupalRoot . '/autoload.php',
  $drupalRoot . '/vendor/autoload.php',
  dirname($drupalRoot) . '/vendor/autoload.php',
] as $candidate) {
  if ($candidate !== '/autoload.php' && is_file($candidate)) {
    $autoload = $candidate;
    break;
  }
}
if ($autoload === NULL) {
  throw new RuntimeException('Could not find Composer autoload.php.');
}

$loader = require $autoload;
$bootstrap = $drupalRoot . '/core/includes/bootstrap.inc';
if (!is_file($bootstrap)) {
  throw new RuntimeException('Could not find core/includes/bootstrap.inc.');
}
require_once $bootstrap;
$loader->addPsr4('Drupal\\audit_chain\\', dirname(__DIR__, 2) . '/src');
foreach (['mysql', 'pgsql'] as $driver) {
  $loader->addPsr4('Drupal\\' . $driver . '\\', $drupalRoot . '/core/modules/' . $driver . '/src');
}

$input = json_decode(stream_get_contents(STDIN), TRUE, 512, JSON_THROW_ON_ERROR);

foreach ($input['namespaces'] as $namespace => $path) {
  $loader->addPsr4($namespace, $path);
}

$prefix = $input['database']['prefix'] ?? '';
if (is_array($prefix)) {
  $prefix = $prefix['default'] ?? '';
}
// Only test-prefixed tables are eligible. Never use an ordinary site schema.
if (!preg_match('/^test[0-9]+/', (string) $prefix)) {
  throw new RuntimeException('A kernel-test table prefix is required.');
}

$builder = new class('appendWorker') extends TestCase {

  /**
   * Supplies isolated verification state for the recovery worker.
   */
  public function recoveryState(): StateInterface {
    return $this->createMock(StateInterface::class);
  }

  /**
   * Builds a real logger with synthetic request and signing services.
   */
  public function build(array $options, bool $recovery = FALSE): AuditChainLogger {
    Database::addConnectionInfo('worker', 'default', $options);
    $config = $this->createMock(ImmutableConfig::class);
    $config->method('get')->willReturnMap([
      ['hash_key', $recovery ? 'recovery_key' : 'serialization_test'],
      ['encryption_profile', NULL],
      ['stream_enabled', FALSE],
    ]);
    $factory = $this->createMock(ConfigFactoryInterface::class);
    $factory->method('get')->willReturn($config);
    $key = $this->createMock(Key::class);
    $key->method('getKeyValue')->willReturn($recovery ? 'synthetic-recovery-secret' : 'synthetic-serialization-key');
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
      new NullLogger(),
      $this->createMock(EncryptServiceInterface::class),
      $this->createMock(EntityTypeManagerInterface::class),
      $this->createMock(StateInterface::class),
    );
  }

};
$logger = $builder->build($input['database'], !empty($input['recovery_fixture']));
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
if (isset($input['activate_segment'])) {
  new Settings(['audit_chain_instance_id' => 'synthetic-instance-a']);
  $segments = new RecoverySegments($database, $logger, new Time(new RequestStack()), $builder->recoveryState());
  $segments->activate($input['activate_segment'], $input['snapshot_digest'], $input['context']);
}
else {
  $logger->logKeyed('test', $input['operation']);
}
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
