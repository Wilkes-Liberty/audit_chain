#!/usr/bin/env php
<?php

/**
 * @file
 * Fail unless PHP openssl is using the OpenSSL 3 FIPS provider.
 *
 * This is the guard for the GitHub Actions FIPS job. It must be able
 * to fail: a host that still hashes MD5 through openssl, or that does
 * not list an active fips provider, exits 1. SHA-256 must still work
 * so a broken OpenSSL install is not mistaken for FIPS enforcement.
 */

declare(strict_types=1);

if (!extension_loaded('openssl')) {
  fwrite(STDERR, "FIPS guard failed: openssl extension is missing.\n");
  exit(1);
}

$version = defined('OPENSSL_VERSION_TEXT') ? OPENSSL_VERSION_TEXT : '';
echo "PHP OPENSSL_VERSION_TEXT: {$version}\n";
if ($version === '' || !str_contains(strtolower($version), 'openssl 3')) {
  fwrite(STDERR, "FIPS guard failed: PHP is not using OpenSSL 3.\n");
  exit(1);
}

if (getenv('OPENSSL_CONF') === FALSE || getenv('OPENSSL_CONF') === '') {
  fwrite(STDERR, "FIPS guard failed: OPENSSL_CONF is empty.\n");
  exit(1);
}
echo 'OPENSSL_CONF=' . getenv('OPENSSL_CONF') . "\n";
echo 'OPENSSL_MODULES=' . (string) getenv('OPENSSL_MODULES') . "\n";

$prefix = getenv('OPENSSL_FIPS_PREFIX');
$providerFile = (is_string($prefix) && $prefix !== '')
  ? $prefix . '/ssl/providers.txt'
  : '';
if ($providerFile === '' || !is_file($providerFile)) {
  fwrite(STDERR, "FIPS guard failed: providers.txt is missing.\n");
  exit(1);
}
$providerText = (string) file_get_contents($providerFile);
echo "openssl list -providers\n{$providerText}\n";
if (!str_contains(strtolower($providerText), 'fips')) {
  fwrite(STDERR, "FIPS guard failed: fips provider is not active.\n");
  exit(1);
}

// Drain leftover errors so the MD5 probe is the only one we inspect.
while (openssl_error_string() !== FALSE) {
  // The queue is discarded.
}

$md5 = @openssl_digest('audit-chain-fips-guard', 'md5');
$md5Error = openssl_error_string();
if ($md5 !== FALSE) {
  fwrite(STDERR, "FIPS guard failed: openssl_digest MD5 succeeded ({$md5}). ");
  fwrite(STDERR, "The FIPS provider is not the default.\n");
  exit(1);
}
echo "openssl_digest MD5 refused";
if (is_string($md5Error) && $md5Error !== '') {
  echo " ({$md5Error})";
}
echo "\n";

while (openssl_error_string() !== FALSE) {
  // The queue is discarded.
}

$sha256 = @openssl_digest('audit-chain-fips-guard', 'sha256');
if ($sha256 === FALSE) {
  fwrite(STDERR, "FIPS guard failed: openssl_digest SHA-256 was refused.\n");
  exit(1);
}
echo "openssl_digest SHA-256 ok ({$sha256})\n";
echo "FIPS provider is active.\n";
exit(0);
