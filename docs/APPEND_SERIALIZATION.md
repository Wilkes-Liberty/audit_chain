# Append serialization

Tracking: [Drupal.org #3623694](https://www.drupal.org/project/audit_chain/issues/3623694).

## Contract

An append takes a database row lock before reading the chain head. The lock and
the new audit row belong to the same transaction. A standalone append commits
before returning. Inside a caller transaction, returning means the append is
pending; the caller's commit or rollback determines durability.

The singleton `{audit_chain_mutex}` row protects an empty chain too. Its value
is not audit evidence. A missing row throws
`AuditChainAppendException`. An unavailable table, deadlock, or database lock
timeout aborts as a database exception. Neither path writes a fork, and neither
retries the caller's business transaction.

The mutex row is created at install (`hook_install`) and by update `10003`. It
is not created on the append path: concurrent first-writers would race on
INSERT. Head read uses `FOR UPDATE` so MySQL reads the current committed head
even when the caller already established a repeatable-read snapshot. SQLite
ignores `FOR UPDATE`; the preceding mutex `UPDATE` takes its write lock.
PostgreSQL retains the mutex row lock until the root transaction ends.

A Drupal lock-backend lease cannot cover this boundary. It can expire, or
commit on a different connection, while the caller's transaction is still open.
Do not reintroduce one. Holding both an external lock and the transaction lock
can introduce lock-order inversion when one caller appends twice.

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
`10003`, replace all old application workers, then resume traffic. A 1.7.x
process does not take the mutex and can still fork against a patched one. The
update creates and seeds only the mutex table; it does not change audit rows,
hashes or seals.

## Why the lock backend was not enough

| Version | Lock backend connection | Result |
| --- | --- | --- |
| 1.7.1 | Same as audit database | B waited; two rows remained linear |
| 1.7.1 | Separate database connection | B returned before A committed; two rows forked |
| Mutex | Same as audit database | B waited; two rows remained linear |
| Mutex | Separate database connection | B waited; two rows remained linear |

This is the independently-committed lock-backend defect. It does not identify
the cause of any historical estate event. Kernel tests cover missing mutex,
caller rollback, a failed head read, an in-process second connection, and
cross-process keyed commit/rollback (PostgreSQL and MySQL). SQLite in-memory
cannot share a mutex across processes, so those two tests skip there.
