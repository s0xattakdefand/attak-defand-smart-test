🌀 Fuzz Testing in Smart Contracts
Fuzz Testing (also called fuzzing) is a technique where randomized, mutated, or high-entropy inputs are sent to contract functions to discover edge cases, unexpected reverts, state drift, or hidden vulnerabilities.

Fuzzing is the core of mutation-based exploit discovery in Web3. Tools like Foundry, Echidna, and Mythril rely on fuzzing to automate security checks, find Zero-Days, and simulate real-world chaos.

✅ Types of Fuzz Testing in Solidity
#	Type	Description
1	Standard Input Fuzzing	Randomized input values for public/external functions.
2	State-Aware Fuzzing	Inputs are generated based on current state of the contract (e.g., balance > 0).
3	Call Sequence Fuzzing	Fuzzes across function sequences, not just isolated calls.
4	Selector Fuzzing	Mutates function selectors (msg.sig) to detect fallback drift or hidden logic.
5	Role-Based Fuzzing	Randomizes caller (msg.sender) and simulates roles (e.g., attacker, owner).
6	Calldata Fuzzing	Mutates raw calldata including structs, arrays, bytes — not just arguments.
7	Gas Fuzzing	Sends calls with varied gasleft() values to detect gas bombs or griefing vectors.
8	Cross-Contract Fuzzing	Simulates calls from one contract to another to explore inter-contract drift.
9	Reentrancy Fuzzing	Fuzzed inputs attempt to trigger fallback or recursive execution.
10	Time-Based Fuzzing	Randomizes block.timestamp, block.number to simulate time-sensitive exploits.

⚔️ What Fuzz Testing Can Expose
Bug Type	Example
Silent Reverts	Logic that fails only under large or rare inputs
Overflow/Underflow	Unhandled arithmetic on edge numbers
Access Drift	Caller without permission triggers logic
Gas Exhaustion	Input causes loops/storage ops that run out of gas
Replay Paths	MetaTx or voting payload can be replayed
Selector Abuse	0xdeadbeef triggers hidden fallback route

🛡️ Defensive Fuzz Strategies
Defense Type	Implementation
Input Bounding	Use vm.assume() or bound() to constrain input ranges
Role Constraints	Use vm.prank() to simulate valid vs invalid access
State Precondition	Use require() guards and fuzz with expected setup
Invariant Anchors	Use invariant_*() to ensure state doesn't drift
Selector Guards	Add selector registry or strict fallback rejection
Event-State Assertions	Log and compare events vs actual state values