♾️ Invariant Testing in Smart Contracts
Invariant Testing ensures that certain conditions (invariants) always hold true — no matter what inputs, sequences, or state transitions occur. It's a core part of formal verification and property-based security for smart contracts.

Unlike unit or integration tests, invariants are not run once — they are checked after every fuzzed call, function sequence, or block of mutated inputs.

✅ If it fails once — you’ve found a bug.

✅ Types of Invariant Testing in Solidity
#	Type	Description
1	Mathematical Invariants	E.g., sum(balances) == totalSupply, a * b == c always.
2	State Relationship Invariants	Related variables are always consistent (e.g., paused == true means transfers fail).
3	Access Invariants	Only specific addresses/roles can change critical state.
4	Reentrancy Guard Invariant	No state drift or balance corruption occurs from reentrancy attempts.
5	Token Flow Invariant	Tokens must move correctly: no inflation, underflow, or misdirection.
6	Upgrade Safety Invariant	Logic upgrades never break storage layout or role preservation.
7	Selector Lock Invariant	Only whitelisted function selectors should execute.
8	Time/Gas/Call Invariants	Calls under certain time or gas ranges must preserve state.
9	Multicall Invariants	Batch execution must leave the system in a valid state.
10	Event-State Match Invariant	Emitted events should match the real internal state transitions.

⚔️ What Invariant Testing Catches
Bug Type	Description
Math Drift	totalSupply != sum(balances) due to rounding/overflow
Access Drift	Random user modifies protected state
Role Erasure	Upgrades delete or override role assignments
Token Burn Drift	Token sent to 0x0 without burning totalSupply
Fallback Abuse	Fuzzed selector triggers undeclared logic
Event Spoofing	Events emitted, but state didn’t change

🛡️ Best Practices for Invariant Testing
Tip	Strategy
Use invariant_*()	Named convention ensures Foundry runs it repeatedly
Fuzz inputs first	Let Foundry or Echidna mutate public/external calls
Track roles/state	Map balances, owners, flags over time and assert correctness
Use bound()	Restrict input ranges to prevent garbage paths
Use snapshots	Snapshot storage for before-after comparison
Use vm.prank()	Simulate role-based drift attempts