🔢 Types of Event Assertions

| Type | Name                                 | Description                                                                                                                           |
| ---- | ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | **Existence Assertion**              | Asserts that a specific event was emitted (e.g., `expectEmit`, `expectEvent`).                                                        |
| 2    | **Order Assertion**                  | Asserts that events were emitted in a specific order during a multi-step call (important for multicall or batch logic).               |
| 3    | **Argument Match Assertion**         | Asserts that event arguments match expected values (e.g., correct `msg.sender`, `amount`, or `role`).                                 |
| 4    | **Indexed Topic Assertion**          | Asserts that indexed fields (topics) in events were emitted correctly (used in off-chain filtering and security rules).               |
| 5    | **No-Emit Assertion**                | Asserts that a specific event was **not** emitted (e.g., to catch backdoor calls or unexpected fallback behavior).                    |
| 6    | **Cross-Contract Emit Assertion**    | Asserts that an external or delegatecalled contract emitted an expected event (used in proxy, plugin, or module systems).             |
| 7    | **Emit-Revert Boundary Assertion**   | Ensures events emitted **before** a revert are discarded and not incorrectly logged.                                                  |
| 8    | **Event State Sync Assertion**       | Asserts that emitted event values match real contract state (e.g., balance updates in `Transfer` events).                             |
| 9    | **Mocked Event Injection Assertion** | Tests whether a malicious contract can emit spoofed events and whether they’re caught (used in audit fuzzing).                        |
| 10   | **Chain Context Assertion**          | Verifies that events include the correct `block.number`, `chainId`, or `tx.origin` (especially in cross-chain bridges or L2 rollups). |

