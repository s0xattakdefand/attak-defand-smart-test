🔢 Types of Hidden State Drift

| Type | Name                                | Description                                                                                                                                          |
| ---- | ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | **External Contract Drift**         | Internal state depends on another contract’s state which may change asynchronously or be manipulated (e.g., `balanceOf()` from an ERC20 token).      |
| 2    | **Storage Collision Drift**         | Due to improper proxy or inheritance setups, storage slots overlap and cause unexpected changes (e.g., proxy + logic conflict).                      |
| 3    | **Unchecked External Return Drift** | Relying on return values from external calls without validation (e.g., `lowLevelCall()` returns success but no effect).                              |
| 4    | **Oracle or Price Feed Drift**      | Using stale or manipulated oracle data for internal decisions (e.g., Chainlink price updates lagging behind).                                        |
| 5    | **Cross-Function State Desync**     | One function modifies shared state in ways not expected by others (e.g., `deposit()` mutates internal state without `withdraw()` accounting for it). |
| 6    | **Event-Driven UI Drift**           | Frontend relies on events that are not aligned with internal state (e.g., event emits success, but state was reverted later).                        |
| 7    | **Gas Exhaustion Drift**            | A transaction partially executes until out-of-gas, leaving incomplete internal state changes (common in large loops).                                |
| 8    | **Shadow Storage Drift**            | Storage modified via `delegatecall` or `assembly` that bypasses typical function flow and logic gates.                                               |
| 9    | **Fallback-based State Drift**      | Unexpected `fallback()` or `receive()` calls mutate internal state when ETH is sent or low-level calls hit unimplemented selectors.                  |
| 10   | **Reentrancy Drift**                | State changed during reentrant call sequence, leading to mismatched assumptions (especially `msg.value`, `balances`, flags).                         |
