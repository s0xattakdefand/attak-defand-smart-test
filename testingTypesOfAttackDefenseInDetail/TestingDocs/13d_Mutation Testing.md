🧬 Mutation Testing in Smart Contracts
Mutation Testing evaluates the strength of your test suite by intentionally injecting small code changes (mutants) into the contract and checking whether your tests detect and fail those changes. If tests still pass after the logic is subtly broken — your tests are not strong enough.

In smart contracts, mutation testing is used to simulate:

🔁 Logic drift

🧟 Zombie function behavior

🔓 Access bypass

🧨 Gas or state explosion

🔐 Missed revert guards

✅ Types of Mutation Testing in Solidity
#	Type	Description
1	Arithmetic Mutations	Change + to -, * to /, etc., to test math validation.
2	Condition Flip Mutations	Flip == to !=, > to <, or invert require() logic.
3	Access Control Mutations	Remove or comment onlyOwner, hasRole() modifiers.
4	Revert Removal	Remove require or revert statements to simulate faulty guard logic.
5	Storage Drift Mutations	Change variable order, visibility, or layout to simulate upgrade bugs.
6	Event Tampering	Emit fake event data or remove event entirely.
7	Fallback Drift	Inject selector or delegatecall routes into fallback().
8	Gas Bomb Injection	Replace simple logic with unbounded loop or storage writes.
9	Dead Code Mutation	Inject logic that's never hit and test coverage failure.
10	Calldata Mutation	Flip calldata encoding or selector logic during fuzz.

⚔️ What Mutation Testing Reveals
Weakness	Example
Untested Guards	require(owner == msg.sender) removed, tests still pass.
Broken Math	+ flipped to -, tests don't catch it.
Event Mismatch	Event emits wrong value, not caught by assertions.
Role Drift	onlyOwner removed, test suite passes silently.
Dead Logic	Function with no coverage remains undetected.

🛡️ How to Defend with Mutation Testing
Practice	Description
Assertion Strength	Always check return values, state, and events.
Negative Testing	Ensure every require() has a failing test.
Revert Reason Coverage	Check that each revert fires with expected reason.
vm.expectRevert()	Guard paths must explicitly expect failure.
Fuzz with Property Checks	Use assertEq(), assertGe(), or invariants across random input sets.
