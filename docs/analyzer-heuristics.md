# Analyzer heuristics and their limits

The `Analyze` function examines an authorization entry and returns a ranked list
of findings. This is a structural analysis only. **It does not decode contract
arguments, verify contract behavior, or provide any safety guarantee.** It only
surfaces patterns that operators commonly want to review before signing.

An analyzer that looks authoritative and is not is worse than none. The limits
are just as visible as the findings: what the analyzer cannot see, it cannot
protect you against.

## Heuristics

### SOURCE_ACCOUNT_WITH_DELEGATES

- **Severity:** Critical
- **What it catches:** A malformed entry where the `SOURCE_ACCOUNT` credential
  arm carries a delegate array.
- **What it misses:** It does not check if the transaction envelope is actually
  signed by the source account. The host enforces the envelope signature.

### DELEGATE_DEPTH_EXCEEDED

- **Severity:** Warning
- **What it catches:** A delegate tree whose nesting depth exceeds
  `MaxDelegateDepth`. Deeply nested delegates are harder to audit.
- **What it misses:** It does not verify if the nested delegates are actually
  authorized by the account's policy. Only the contract's `__check_auth` can do
  that.

### DELEGATE_COUNT_HIGH

- **Severity:** Warning
- **What it catches:** A delegate tree with a total number of nodes exceeding
  `MaxTotalDelegates`. Broad trees increase coordination complexity.
- **What it misses:** It cannot evaluate if all these delegates are actually
  necessary for the transaction to succeed.

### SUB_INVOCATION_COUNT_HIGH

- **Severity:** Warning
- **What it catches:** A deep or broad invocation tree authorizing more
  sub-invocations than `MaxSubInvocations`. Complex trees are harder to audit.
- **What it misses:** It does not understand what the invocations actually _do_,
  what arguments they take, or whether they are malicious. It only counts them.

### EXPIRATION_FAR_FUTURE

- **Severity:** Warning
- **What it catches:** A signature expiration (`ValidUntilLedger`) that is far
  in the future compared to the current ledger (exceeding
  `MaxValidUntilLedgerDelta`).
- **What it misses:** It cannot enforce the network's `max_live_until_ledger`
  ceiling, which is governed by network consensus and ultimately enforced by the
  host.

### CONTRACT_UNKNOWN

- **Severity:** Warning
- **What it catches:** A root contract address that is not present in the
  caller's `KnownContracts` list.
- **What it misses:** It does not verify the contract's actual behavior, its
  Wasm hash, or whether a previously known contract has been upgraded to
  something malicious.

### UNSIGNED_DELEGATES

- **Severity:** Info
- **What it catches:** Delegate nodes that do not yet carry a signature.
- **What it misses:** It cannot know the account's actual policy. It does not
  know whether those missing signatures will cause the transaction to fail, or
  if the account only requires a subset of them to succeed.

### EXPIRATION_ZERO

- **Severity:** Critical
- **What it catches:** An expiration (`ValidUntilLedger`) set to 0.
- **What it misses:** This is a hard structural failure. It is unconditionally
  invalid for non-source-account credentials, as the host treats 0 as expired at
  genesis.

### LEGACY_CREDENTIALS_NOT_ADDRESS_BOUND

- **Severity:** Info
- **What it catches:** The use of legacy `SOROBAN_CREDENTIALS_ADDRESS`
  credentials, which do not bind the signer's address into the payload.
- **What it misses:** It cannot know if the specific contract mitigates the
  replay vulnerability itself (e.g., by safely binding the address in its
  arguments). It flags the structural risk regardless.
