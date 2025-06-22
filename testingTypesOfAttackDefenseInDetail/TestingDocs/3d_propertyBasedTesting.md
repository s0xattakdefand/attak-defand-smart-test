🧪 Property-Based Testing in Smart Contracts
Property-Based Testing (PBT) focuses on testing that certain properties or invariants always hold, regardless of the inputs. Rather than specifying exact inputs and outputs like unit tests, PBT uses randomized inputs (fuzzing) and verifies that your contract never violates safety or logical rules.

In Solidity, this is critical for catching:

❌ Hidden logic drift

🐛 Unsafe edge cases

💣 Gas bombs and state mutations

🔁 Replay/resend issues

📉 Invariants that silently fail

✅ Types of Property-Based Testing
#	Type	Description
1	Mathematical Invariants	E.g., balanceOf[a] + balanceOf[b] == totalSupply.
2	State Invariants	State should never violate certain properties (e.g., paused == true means no transfers).
3	Access Control Invariants	Unauthorized callers should never mutate protected state.
4	Gas Usage Invariants	Gas usage should stay below a threshold or not explode under fuzzed inputs.
5	Event-State Consistency	If event emitted, it must match actual storage change.
6	Idempotency	Calling same function repeatedly with same input yields same result.
7	Revert Condition Testing	Always reverts under defined bad conditions.
8	Monotonicity / Bounds Testing	Values only grow, shrink, or stay within defined range.
9	Fuzz-Fallback Route Protection	Fuzzed selectors should never unlock fallback exploits.
10	Commutativity / Cross-State	A + B = B + A style behaviors across contracts hold true.

⚔️ What Property-Based Testing Prevents
Bug Type	Example
Silent Reverts	Reverts triggered only at extreme inputs missed in unit test
Role Break	Random fuzzed caller mutates admin state
Token Drift	totalSupply gets out of sync with balances after fuzz
Upgrade Break	New logic fails existing invariants
Gas Bomb	Calldata triggers storage explosion on loop fuzz
Math Drift	Underflow/overflow in complex bonding curves