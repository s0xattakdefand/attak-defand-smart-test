🔢 Types of False Positive Test Logic

| Type | Name                                   | Description                                                                                                        |
| ---- | -------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| 1    | **Missing Revert Expectation**         | Test doesn't assert that a function should revert, so failing logic passes silently.                               |
| 2    | **Overbroad Try-Catch**                | Catch block swallows all failures without asserting specific error reasons.                                        |
| 3    | **Incorrect Assertion Target**         | Asserts on the wrong variable or state (e.g., `assert(x == 1)` instead of `assert(balance[msg.sender] == 1)`).     |
| 4    | **Event-only Verification**            | Tests only for emitted events but not actual state change (events can be spoofed without effect).                  |
| 5    | **Inconsistent Mock Behavior**         | Using mocks that don't simulate real contract behavior properly, leading to misleading pass results.               |
| 6    | **Unverified Return Values**           | Function called without checking or asserting its return value (e.g., no check on `bool success = transfer(...)`). |
| 7    | **Hardcoded Assumptions**              | Test uses static inputs that never explore edge cases or dynamic behavior.                                         |
| 8    | **Lack of Negative Tests**             | Only successful paths are tested, no invalid or attack paths simulated.                                            |
| 9    | **Outdated Test State**                | Reusing state between tests or failing to reset state, causing one test’s success to affect another’s logic.       |
| 10   | **False Solidity Test Fuzzing Oracle** | Fuzz test passes because fuzzing oracle doesn’t track internal changes, only final return values.                  |
