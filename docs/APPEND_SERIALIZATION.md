# Append serialization

Tracking: [Drupal.org #3623694](https://www.drupal.org/project/audit_chain/issues/3623694).

## Contract

An append takes a database row lock before reading the chain head. The lock and
the new audit row belong to the same transaction. A standalone append commits
before returning. Inside a caller transaction, returning means the append is
pending; the caller's commit or rollback determines durability.

The singleton `audit_chain_mutex` row protects an empty chain too. Its value is
not audit evidence. An unavailable table, deadlock or database lock
timeout aborts the append. The implementation does not silently fall back to an
unserialized write or retry the caller's business transaction.

The native database upsert creates or locks the singleton in one atomic
statement. It requires no seed step and handles first writes before Drupal
invokes the module install hook. Its affected-row count is not used to infer
lock ownership. The row stores no chain head or evidence.

The head read uses `FOR UPDATE` so MySQL reads the current committed head even
when the caller already established a repeatable-read snapshot. SQLite ignores
`FOR UPDATE`, but the preceding mutex update takes its write lock. PostgreSQL
retains the mutex row lock until the root transaction ends. At stricter isolation
levels, a serialization failure must propagate to the caller.

The legacy lock constructor argument remains accepted for compatibility. It no
longer controls append serialization. A three-second external lease cannot
protect an arbitrarily long caller transaction. Holding both an external lock
and the transaction lock can introduce lock-order inversion when one caller
appends twice, so the implementation uses only the database lock.

## Consumer obligations

Evidence-required consumers must let append failures abort the governed action.
Retry the entire business transaction only when its operations are safe to
retry. Best-effort consumers need their own durable retry/outbox path. The
request-scoped collector is not a durable queue.

Avoid long caller transactions. The mutex serializes all writers and can expose
existing business-table lock-order inversions as deadlocks. Configure database
lock/statement timeouts appropriate to the application; this change does not
silently alter connection-wide timeout settings. Stream messages remain
operational notifications and are not proof that an outer transaction committed.

## Upgrade

Quiesce all writers, including web, queue, cron and CLI workers. Apply update
10003, replace all old application workers, then resume traffic. An old worker
that does not take the new mutex can still fork the chain. The update creates
only the mutex table; it does not change audit rows, hashes or seals.
An unavailable serialization table fails visibly. Creating a missing singleton
row uses a native atomic upsert, never a read-then-insert sequence.

## Validation so far

Two separate Drush processes on PostgreSQL 16 tested a four-second outer
transaction against a competing append. Synthetic tables contained no customer
records and were dropped after each probe.

| Version | Lock backend connection | Result |
| --- | --- | --- |
| 1.7.1 | Same as audit database | B waited; two rows remained linear |
| 1.7.1 | Separate database connection | B returned before A committed; two rows forked |
| Candidate | Same as audit database | B waited; two rows remained linear |
| Candidate | Separate database connection | B waited; two rows remained linear |

This confirms a defect with independently committed lock backends. It does not
identify the cause of any historical estate event. A separate rollback-only
probe also confirmed that 1.7.1 writes after `acquire()` returns false.

The permanent keyed concurrency tests fail against unmodified 1.7.1 and pass
against this candidate. They cover commit and rollback, an initially absent
mutex row, and a stale MySQL repeatable-read snapshot. CI runs them on PostgreSQL
16 and MySQL 8.0; SQLite runs the remaining kernel tests.

Local full-suite results on Drupal 11.4.6 / PHP 8.4.24:

- PostgreSQL 16: 84 tests, 458 assertions, one optional Charts integration skip.
- MariaDB 11.4: 84 tests, 458 assertions, the same skip.
- SQLite: 84 tests, 446 assertions; the two process tests are skipped in addition
  to optional Charts because in-memory SQLite cannot be shared by processes.

Existing dependency deprecations were reported. A separate PostgreSQL timeout
probe aborted at approximately 250 ms, left no active append transaction, and
allowed a later append; only the two successful rows remained. A forced
business-lock deadlock scenario and SQLite file-based contention are still
release-review gaps. They are not established by the happy-path kernel suite.
