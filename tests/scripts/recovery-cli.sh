#!/usr/bin/env bash
# Run from a disposable Composer Drupal project, never an existing site.
set -euo pipefail
if [[ "${AUDIT_CHAIN_CLI_TEST:-}" != 1 || -f web/sites/default/settings.php ]]; then
  echo 'Requires AUDIT_CHAIN_CLI_TEST=1 and an uninstalled disposable Drupal project.' >&2
  exit 2
fi
fixture_dir="$(mktemp -d)"
trap 'rm -rf "$fixture_dir"' EXIT
drush=vendor/bin/drush
"$drush" site:install minimal --db-url="sqlite://localhost/$fixture_dir/site.sqlite" \
  --account-pass=synthetic-cli-test-only --yes
chmod u+w web/sites/default/settings.php
printf '\n%s\n' '$settings["audit_chain_instance_id"] = "synthetic-cli-instance";' >> web/sites/default/settings.php
"$drush" pm:enable audit_chain --yes
"$drush" php:script web/modules/contrib/audit_chain/tests/fixtures/recovery-cli-setup.php
"$drush" audit-chain:recovery-activate --help > "$fixture_dir/help.txt"
"$drush" audit-chain:seal --help > "$fixture_dir/seal-help.txt"
if "$drush" audit-chain:seal --through=3 --reason=synthetic-cli-refusal --no > "$fixture_dir/seal-refused.txt" 2>&1; then
  echo 'Explicit --no unexpectedly sealed the prefix.' >&2
  exit 1
fi
"$drush" php:eval 'if (\Drupal::service("audit_chain.logger")->getSeal() !== NULL) { throw new \RuntimeException("Refusal created a seal"); }'
"$drush" audit-chain:recovery-prepare > "$fixture_dir/prepare.json"
jq -e '.historical_verdict.ok == false' "$fixture_dir/prepare.json" >/dev/null
snapshot="$(jq -r .snapshot_digest "$fixture_dir/prepare.json")"
segment=31525a16-af7b-4b37-81e1-1fe8d4a4dbae
args=(audit-chain:recovery-activate "--segment=$segment" "--snapshot=$snapshot"
  --incident=synthetic-cli-test --reason='Exercise the installed Drush command.'
  --approved-by=synthetic-test --backup-digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)
if "$drush" "${args[@]}" --no > "$fixture_dir/refused.txt" 2>&1; then
  echo 'Explicit --no unexpectedly activated recovery.' >&2
  exit 1
fi
"$drush" php:eval 'if (\Drupal::database()->select("audit_chain_recovery", "r")->countQuery()->execute()->fetchField() != 0) { throw new \RuntimeException("Refusal persisted recovery"); }'
"$drush" "${args[@]}" --yes > "$fixture_dir/activate.json"
jq -e '.verification.segment_ok == true and .historical_ok == false' "$fixture_dir/activate.json" >/dev/null
"$drush" "${args[@]}" --yes > "$fixture_dir/retry.json"
"$drush" audit-chain:recovery-verify "$segment" > "$fixture_dir/verify.json"
jq -e '.segment_ok == true and .historical_ok == false' "$fixture_dir/verify.json" >/dev/null
"$drush" audit-chain:recovery-export "$segment" > "$fixture_dir/export.json"
jq -e '.verification.segment_ok == true and .verification.historical_ok == false' "$fixture_dir/export.json" >/dev/null
"$drush" php:eval 'if (\Drupal::service("audit_chain.logger")->verify()["ok"] || \Drupal::database()->select("audit_chain_recovery", "r")->countQuery()->execute()->fetchField() != 1) { throw new \RuntimeException("Historical failure or retry contract changed"); }'
if "$drush" audit-chain:seal --through=3 --reason=synthetic-frozen-history --yes > "$fixture_dir/seal-frozen.txt" 2>&1; then
  echo 'Confirmed sealing must still refuse frozen successor history.' >&2
  exit 1
fi
grep -q 'recovery' "$fixture_dir/seal-frozen.txt"
echo 'Installed CLI discovery, refusal, activation, retry, verification and export passed.'
