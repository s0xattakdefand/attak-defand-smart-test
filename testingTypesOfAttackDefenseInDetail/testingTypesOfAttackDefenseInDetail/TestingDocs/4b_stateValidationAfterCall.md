🔢 Types of State Validation After Calls

| Type | Name                                | Description                                                                                                              |
| ---- | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| 1    | **Balance State Validation**        | Verifying `balances`, `totalSupply`, or `msg.value`-related changes post call.                                           |
| 2    | **Storage Slot Integrity Check**    | Ensuring that critical storage variables (like owner, admin, paused) remain unchanged after external/internal calls.     |
| 3    | **Cross-Contract State Validation** | Checking that downstream contract state (e.g., in token or oracle) aligns with the expected result.                      |
| 4    | **Event-State Match Validation**    | Ensuring that emitted events match actual state changes — not spoofed or misleading logs.                                |
| 5    | **Snapshot-Based Validation**       | Using snapshots before a call and comparing post-call to catch hidden changes.                                           |
| 6    | **Hash-Based State Commitment**     | Hashing state before/after execution (e.g., `keccak256(abi.encode(...))`) to detect mutations.                           |
| 7    | **Role or Access Drift Validation** | Ensuring role/permission assignments didn’t silently change mid-call (via `delegatecall`, storage drift, etc).           |
| 8    | **Gas-Left State Dependency**       | Validating that operations left enough gas and didn’t cause silent revert halfway.                                       |
| 9    | **Reentrancy-Invariant Validation** | Ensuring expected flags, status, or intermediate state wasn’t corrupted by reentrant logic.                              |
| 10   | **Interface Return Validation**     | Confirming that the return value from external calls (e.g., ERC20 `transfer`) was successful, and that state matches it. |


