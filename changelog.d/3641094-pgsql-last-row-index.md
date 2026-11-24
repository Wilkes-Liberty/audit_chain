---
section: Fixed
---
On PostgreSQL, reading the last log row no longer scans and sorts the whole
`audit_chain_log` table. The pgsql driver renders `orderBy('id', 'DESC')` as
`DESC NULLS LAST`, which the primary key cannot serve, and the append path ran
that lookup on every event while holding the chain mutex. Last-row and
first-row-after lookups now use `MAX(id)` and `MIN(id)` through the primary key
on every driver (#3641094).
