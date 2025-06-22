🏁 Race Condition in Smart Contracts
A Race Condition occurs when two or more transactions (or calls) compete to access or modify the same state, leading to unexpected, inconsistent, or exploitable outcomes.

These vulnerabilities are dangerous in DeFi, DAOs, and bridge contracts — where timing, ordering, or replay behavior can be exploited.

✅ Types of Race Conditions
#	Type	Description
1	Front-Running Race	Attacker watches mempool and submits a faster or higher gas tx to beat another.
2	Cross-Function Race	Function A and B use the same state, but are called simultaneously and conflict.
3	Reentrancy-Based Race	A reentrant call mutates shared state before original logic finishes.
4	DAO Proposal Execution Race	Voting or execution race in governance systems — two users execute at the same threshold.
5	Storage Write Race	Two writes to the same storage slot collide across overlapping calls.
6	Call-After-Check Race (TOCTOU)	A state is checked (require(x == 1)) and then acted upon, but state changes in between (Time-of-check-time-of-use).
7	Gas Race	Contracts fail or succeed based on gas stipend left — can be gamed to control race timing.
8	Cross-Chain Race	Competing L1 and L2 messages processed in different order across bridges.
9	Meta-Transaction Race	Multiple relayers submit the same signed tx — one succeeds, others may fail or front-run.
10	Multicall Race	Inside a multicall, one subcall affects another in an unintended way due to shared state or ordering.

⚔️ Attack Examples
Type	Exploit
Front-Running	Sandwich attacker places tx before and after victim's swap.
Reentrancy Race	Vault allows attacker to drain before balance is updated.
MetaTx Race	Two relayers use same signed tx to trigger race between duplicate txs.
Multicall Race	In batchTransfer, attacker drains tokens before allowances are decremented.

🛡️ Defense Strategies
Type	Defense
Front-Running	Add commit-reveal pattern or MEV protection (e.g., flashbots, Fair Sequencing).
Reentrancy	Use nonReentrant modifier and update state before external calls.
MetaTx Race	Track nonce for each signer; enforce unique tx IDs.
Cross-Function	Lock or isolate shared state with guards or mutexes.
Multicall Race	Use memory caching or subcall context isolation.