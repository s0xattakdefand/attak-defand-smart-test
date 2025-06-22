🔄 Revert Expectation Tests in Smart Contracts
Revert Expectation Tests ensure that a function call fails with a specific reason, error string, or custom error — when invalid inputs, permissions, or states are triggered. These are a critical subset of negative tests, providing strong guarantees that the contract fails exactly how and where it should.

✅ If a function should fail under bad input — your test must prove it reverts for the right reason.

✅ Types of Revert Expectation Tests
#	Type	Description
1	Generic Revert Test	Expect any revert when calling unsafe or invalid input.
2	Exact String Revert Test	Expect a specific revert reason like "Not owner" or "Too much".
3	Custom Error Revert Test	Expect a specific error MyError() defined in the contract.
4	Revert on Access Violation	Unprivileged user attempts admin/owner role call.
5	Revert on Insufficient Balance	User tries to withdraw more than available.
6	Revert on Invalid State	Function called in wrong phase (e.g., paused, not initialized).
7	Revert on Signature Validation	Invalid v, r, s causes ECDSA or MetaTx failure.
8	Revert on Overflows/Underflows	Invalid math, array indexing, or unchecked usage breaks logic.
9	Fallback Selector Revert	Drifted selector triggers fallback with rejection.
10	Oracle / External Call Revert	External call returns stale/invalid data and fails validation.

⚔️ Attack Types Prevented by Revert Tests
Attack Type	Description
Access Control Bypass	Proves that only the correct roles succeed.
Logic Drift / Off-by-One	Reverts correctly when at or near logic boundary.
Permit Replay	Reverts reused signature or wrong nonce.
Reentrancy Path Abuse	Detects logic drift where a call is reentered before state update.
Fallback Selector Trigger	Protects against drifted selector activating unexpected logic.
Upgrade Injection	Simulates failed upgrade due to unsafe storage layout or caller.
Commit-Reveal Replay	Fails on reused commit hash or mismatched reveal.
Overflow Error	Math operation goes over type limit — expect revert.
Invalid ZK Proof	Revert on bad nullifier, mismatched input, or drifted circuit.

🛡️ Defense Types Strengthened by Revert Tests
Defense Type	Description
✅ require() Guards	Enforced at runtime via vm.expectRevert() tests.
✅ Access Modifiers	Verifies onlyOwner, hasRole, and custom guards behave correctly.
✅ SafeMath Bounds	Proves math reverts when type boundaries are violated.
✅ State Machine Control	Locks functionality by phase/condition and tests it.
✅ Custom Errors	Protects logic clarity via error NotAuthorized() vs generic revert().
✅ Signature Validators	Prevents misuse of signer roles via revert-on-failure.
✅ Fallback Guards	Reject drifted function selectors.
✅ Nonce / Hash Guards	Reject reused or malformed payloads.