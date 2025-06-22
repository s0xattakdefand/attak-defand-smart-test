⚙️ Term: Computer Numerical Control (CNC) — Web3 / Smart Contract Security Context
Computer Numerical Control (CNC) refers to the automated control of physical machinery (like lathes, routers, 3D printers) using programmed code. In the Web3 context, CNC is abstracted to:

Automated control over decentralized processes via pre-programmed smart contract logic, where precise, deterministic operations are executed on-chain or across DAOs, vaults, relayers, and L2 systems — enabling repeatable, auditable, and programmable decentralized execution.

📘 1. Types of CNC-Like Systems in Web3
CNC Equivalent in Web3	Description
Automated Vault Controllers	Code-driven asset management logic for farming, staking, or rebalancing
Smart Order Routers (SOR)	Programmed DEX aggregators that route trades deterministically
Governance Execution Engines	Executes DAO proposals with multi-step programmed logic
Bridge Relay Executors	Follows encoded relay instructions across chains
zkRollup Batch Executors	Automates prover → verifier → finalizer steps for state settlement
SimStrategyAI CNC Mode	Autonomously executes repeatable fuzz simulations

💥 2. Attacks on CNC-Like Systems in Web3
Attack Type	Description
Logic Injection	Malicious data injected into programmable execution steps
Opcode Abuse	CNC loop uses delegatecall, create2, or unexpected opcode paths
Step Drift / Mutation	Mutation of execution sequence due to upgrade, delay, or external hook
Bridge Relay Override	CNC logic misrouted through spoofed relay
Proposal Batch Poisoning	DAO CNC logic packed with malicious sub-actions
zk Execution Abuse	CNC prover completes batch with invalid state transitions

🛡️ 3. Defenses for Web3 CNC Execution
Defense Strategy	Implementation Method
✅ Execution Step Validation	Use on-chain hash precommit or step tracking to verify CNC sequences
✅ Opcode Filtering	Restrict usage of dangerous opcodes in CNC pipelines
✅ DAO Proposal Simulation	CNC logic must pass simulation tests before being committed
✅ Relay Authentication	All CNC relays verified with signer threshold or zk proof
✅ Step Replay Guard	Prevent replaying or reordering CNC steps across epochs
✅ Audit Log Integration	All CNC executions emitted via structured logs for verification

✅ 4. Solidity Code: CNCExecutor.sol
This contract:

Registers programmable CNC task sequences

Executes steps deterministically

Logs execution results and prevents replays

Can enforce hash-locked validation of step logic