💥 Gas Bombs in Smart Contracts
Gas bombs are malicious or unintentional operations that cause a transaction to consume excessive gas, leading to:

❌ DoS (Denial of Service)

🐛 Partial state commits

🧨 Failed meta-transactions

🔄 Broken loops or halted batched execution

They’re often invisible to standard tests, and become deadly when combined with multicall, fallback, or reentrancy.

✅ Types of Gas Bombs
#	Type	Description
1	Loop Bomb	Unbounded or user-controlled loops that consume excessive gas.
2	Delegatecall Bomb	Called logic has expensive operations, consuming gas from the caller’s context.
3	Reentrancy Depth Bomb	Recursive fallback calls exhaust call stack and gas.
4	Event Bomb	Emits too many or oversized events (with indexed fields) that increase gas.
5	Storage Bomb	Expensive writes to mappings, arrays, or deep structs (SSTORE heavy logic).
6	Calldata Bomb	Malicious or oversized input arrays consume gas during decoding or iteration.
7	Fallback Selector Bomb	Unknown selector hits a fallback that does heavy gas work.
8	External Call Bomb	Target contract performs gas-heavy logic or infinite loops.
9	Proxy Upgrade Bomb	New logic implementation contains gas-draining code — breaks proxy invocations.
10	ERC20/Token Hook Bomb	Transfer hooks (e.g., onTransfer, onApprove) do unbounded work.

⚔️ Attack Patterns
Type	Exploit
Loop Bomb	Pass 10,000 elements into batchTransfer() — crashes the loop.
Delegatecall Bomb	Delegate to gas-intensive logic (e.g., while(true) {} inside implementation).
Reentrancy Bomb	Call a vault, trigger fallback, re-enter until stack/gas overflow.
Calldata Bomb	Use abi.encodePacked() to send max-sized payloads.
Event Bomb	Emit 50 events with indexed address — gas drain via logs.
External Bomb	call() another contract that intentionally never returns or consumes all gas.

🛡️ Defense Strategies
Type	Defense
Loop Bomb	require(input.length < safeLimit) — limit array length.
Delegatecall Bomb	Audit target logic + use static analysis on implementation.
Reentrancy Bomb	Add nonReentrant modifier.
Calldata Bomb	Bound decoding with require(data.length < max).
Storage Bomb	Use caching, map caps, or restrict batch sizes.
Event Bomb	Limit emit frequency and size — especially in loops.
External Bomb	Always check low-level call returns and set gas caps.