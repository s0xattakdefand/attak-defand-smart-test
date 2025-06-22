🔢 Types of Full Revert Coverage

| Type | Name                                       | Description                                                                                                        |
| ---- | ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------ |
| 1    | **Access Control Revert Coverage**         | Tests that unauthorized users are rejected from role-restricted functions (`require(hasRole(...))`).               |
| 2    | **Input Validation Revert Coverage**       | Tests that invalid or edge-case inputs (e.g., zero address, negative amount) revert with the correct error.        |
| 3    | **State Precondition Revert Coverage**     | Verifies that invalid state conditions (e.g., withdrawing with zero balance) trigger reverts.                      |
| 4    | **Arithmetic Overflow/Underflow Coverage** | Ensures math operations that would overflow/underflow revert properly (under `SafeMath` or by default in >=0.8.0). |
| 5    | **External Call Failure Coverage**         | Tests reverts when external contract calls fail (e.g., `ERC20.transfer()` returns false).                          |
| 6    | **Reentrancy Protection Coverage**         | Verifies that reentrant calls correctly revert via `nonReentrant` or reentrancy guard logic.                       |
| 7    | **Paused/Disabled State Coverage**         | Ensures actions revert when the contract is paused or in a shutdown mode.                                          |
| 8    | **Modifier Logic Revert Coverage**         | Checks that each `require()` inside modifiers triggers correct reverts under invalid conditions.                   |
| 9    | **Constructor/Init Revert Coverage**       | Tests deployment with bad constructor arguments or improper initial conditions.                                    |
| 10   | **Fallback & Receive Revert Coverage**     | Ensures unknown function selectors or ETH sends revert if not explicitly handled.                                  |
| 11   | **Upgrade Safety Revert Coverage**         | Verifies that upgrade logic (e.g., `upgradeTo()`) reverts if called by the wrong role, or with bad implementation. |
| 12   | **Custom Error & Reason String Coverage**  | Ensures every revert emits either a custom error or proper string for identification/debugging.                    |
