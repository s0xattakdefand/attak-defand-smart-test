🔢 Types of Missing Negative Test Cases

| Type | Name                                     | Description                                                                             |
| ---- | ---------------------------------------- | --------------------------------------------------------------------------------------- |
| 1    | **Access Control Misses**                | No test that tries unauthorized access (e.g., non-owner calling `sweepFunds()`).        |
| 2    | **Boundary Overflow/Underflow**          | No test with max/min values (e.g., `uint256 max`, `0`, or `type(uint256).max`).         |
| 3    | **Invalid Inputs / Edge Case Arguments** | No test for zero addresses, zero values, `false`, empty arrays, or `null` structs.      |
| 4    | **Reentrancy Simulation**                | No malicious contract used to simulate recursive call behavior.                         |
| 5    | **Double Call / Replay Attempts**        | No test that checks behavior if a function is called again (e.g., `claim()` twice).     |
| 6    | **Permission Drift**                     | No test for expired roles, changed delegates, or removed permissions.                   |
| 7    | **ERC20 Failures**                       | No test for `transfer` or `approve` failure return values (ERC20 doesn’t always throw). |
| 8    | **State Precondition Violations**        | No test where state is in the wrong setup (e.g., withdrawing before depositing).        |
| 9    | **Paused/Disabled Mode**                 | No test where the contract is paused but the action is still attempted.                 |
| 10   | **Fallback & Unknown Selector Paths**    | No test for direct call with bad data or unknown function selectors.                    |
| 11   | **Cross-Contract Failures**              | No test where downstream contract fails (e.g., DEX call or oracle call fails silently). |
| 12   | **Zero Balance / Out-of-Gas Paths**      | No simulation of low gas, low balance, or failed ETH transfers.                         |
