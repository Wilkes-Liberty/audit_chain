---
section: Fixed
---
Delete leftover `audit_chain.witness_demo` state on uninstall so a reinstall cannot revive a stale demo digest. Persist only the current digest; receipt ids stay in the receipt table.
