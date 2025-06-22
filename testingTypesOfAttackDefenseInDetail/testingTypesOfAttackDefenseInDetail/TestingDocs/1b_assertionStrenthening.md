🔢 Types of Assertion Strengthening

| Type | Name                                  | Description                                                                                                                |
| ---- | ------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| 1    | **Invariant Assertion Strengthening** | Adding more specific, unbreakable conditions (`assert`) to protect internal state integrity.                               |
| 2    | **Precondition Strengthening**        | Tightening input requirements (`require`) before execution (e.g., disallowing zero address, non-positive values).          |
| 3    | **Postcondition Strengthening**       | Verifying expected outcomes after execution (e.g., `assert(balance[msg.sender] == oldBalance - amount)`).                  |
| 4    | **Access Control Assertion**          | Explicitly asserting caller roles or permissions even after using modifiers (`assert(hasRole(...))`).                      |
| 5    | **Gas-State Coupling Assertion**      | Asserting expected gas usage behavior to prevent gas bombs or denial-of-service vectors (`assert(gasleft() > threshold)`). |
| 6    | **Temporal Assertion Strengthening**  | Adding time/block-based guards (e.g., `assert(block.timestamp >= unlockTime)`) to validate state transitions.              |
| 7    | **Cross-Contract Return Assertion**   | Validating returned values from external calls using `require` or `assert` instead of trusting them blindly.               |
| 8    | **Memory/Storage Bound Assertion**    | Asserting that array/map length or data range is within bounds (e.g., `assert(i < arr.length)`).                           |
| 9    | **Selector Validation Assertion**     | Ensuring correct function selectors are being routed or decoded, especially in fallback or proxy contracts.                |
| 10   | **Behavioral Drift Assertion**        | Detecting unexpected logic divergence (e.g., using keccak hash comparisons to assert no logic mutation occurred).          |
