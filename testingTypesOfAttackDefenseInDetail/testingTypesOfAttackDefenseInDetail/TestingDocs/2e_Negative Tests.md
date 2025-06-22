🚫 Negative Tests in Smart Contracts
Negative Testing ensures your smart contract fails safely under invalid, malicious, or unexpected conditions. The goal is to verify that reverts, errors, and access rejections work correctly — protecting against logic drift, edge-case exploits, and input abuse.

If your positive tests prove what should work, then negative tests ensure what must not work.

✅ Types of Negative Testing
#	Type	Description
1	Revert Condition Tests	Provide invalid input and assert that require() or revert() triggers.
2	Unauthorized Access Tests	Call protected functions from unprivileged addresses.
3	Invalid Input Tests	Send negative numbers, overflows, zero values, or invalid addresses.
4	State Violation Tests	Call functions in wrong state (e.g., before initialization, when paused).
5	Excess Withdraw/Transfer	Attempt to transfer more than balance.
6	Fallback Abuse Attempt	Trigger fallback with zombie selectors or malformed calldata.
7	Replay & Nonce Reuse Tests	Reuse same signature or proof to simulate replay.
8	Gas Bomb Simulation	Feed high-entropy data or loops to detect DoS vulnerabilities.
9	Upgrade Misuse Test	Simulate unsafe upgrade calls by unauthorized users.
10	Boundary Drift Reverts	Push near-edge valid input into invalid space (e.g., max+1, min-1).

⚔️ Attack Types Caught by Negative Tests
Attack Type	Description
Unauthorized Access	Simulate access by attacker — expect revert("Not owner").
Zero Value Injection	Detect logic errors triggered by empty values (e.g., deposit(0)).
Invalid Selector Replay	Malformed calldata should not execute hidden logic.
Permit Replay	Using the same signature twice triggers rejection.
Invalid Upgrade Execution	Prevent logic or admin upgrades from non-owner.
Fallback Logic Trigger	Prevent unexpected fallback logic activation from drifted selectors.
Over-withdrawal	Catch logic that allows taking more than balance.
Paused Function Call	Test if critical logic rejects calls when paused.
Entropy Drift Injection	Detect edge-case inputs that bypass hash/role protections.
Time Window Violation	Call vote or mint outside of valid block.timestamp range.

🛡️ Defense Types Enforced by Negative Tests
Defense Type	Description
✅ Require & Revert Guards	Ensures all require() paths are enforced and tested.
✅ Access Control Enforcement	Confirms only valid roles succeed.
✅ Bounds Enforcement	Tests input size, numeric limits, and index range.
✅ Pause / Lock Validations	Validates state-machine logic — whenNotPaused, isInitialized.
✅ Fallback Selector Guard	Asserts fallback doesn’t route unintended logic.
✅ Gas Limit Abuse Handling	Confirms no excessive loops or calldata triggers DoS.
✅ Storage/Upgrade Revert Logic	Confirms unsafe upgrade paths are blocked.
✅ Signature Replay Guard	Ensures reused or altered signatures are rejected.
✅ Oracle/Price Mismatch Rejection	Validates stale or incorrect off-chain inputs are discarded.
✅ Invariant Anchoring via Reverts	Forces invalid states to fail, locking logic integrity.

