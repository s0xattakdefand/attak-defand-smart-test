✅ Unit Testing in Smart Contracts
Unit testing is the practice of verifying the correctness of individual functions or components in isolation, without depending on other parts of the contract or system. In Solidity, this means testing one function at a time, with precise control over inputs, outputs, and internal state.

Unit testing is the first line of defense in Web3 security — it catches logic errors, permission bugs, and edge case failures before integration or deployment.

✅ Types of Unit Testing in Solidity
#	Type	Description
1	Positive Test Case	Valid input → expected state/output change.
2	Negative Test Case	Invalid input or access → expect revert/failure.
3	Boundary Test Case	Test edge values (0, max uint, empty strings, etc.).
4	Access Control Test	Test role-restricted functions with/without access.
5	State Transition Test	Validate that state updates correctly across function call.
6	Event Emission Test	Check that the right event with correct data is emitted.
7	Revert Reason Test	Validate revert message or custom error trigger.
8	Gas Usage Test (unit-level)	Benchmark simple function gas cost (in Foundry).
9	Return Value Test	Assert return values exactly match expected output.
10	Mocked Dependency Test	Replace external calls with mock contracts to isolate logic.

⚔️ Common Attack Vectors Caught by Unit Testing
Type	Vulnerability
Logic Flaw	Miscalculated math, incorrect branching (if, else)
Role Misuse	onlyOwner fails to restrict function
Unchecked Return	External call returns false and not handled
Missing Reverts	Bad input doesn't trigger a failure
Event Spoofing	Events emitted don’t match state changes

🛡️ Defense via Unit Testing
✅ Catch reentrancy or state drift in isolation

✅ Ensure storage mutations only occur with valid conditions

✅ Lock function access by simulating role misuse

✅ Protect fallback/selectors by simulating unknown inputs

✅ Prove guards, caps, and boundary limits are enforced

