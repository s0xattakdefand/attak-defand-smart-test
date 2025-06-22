🧩 Term: Context of Use — Web3 / Smart Contract Security & Human Factors Context
Context of Use refers to the conditions under which a system, dApp, smart contract, or security mechanism is intended to be used, including:

🧑‍💻 Who uses it (role, skill, privileges)
🧠 What the purpose is (e.g., governance, minting, bridging)
🌍 Where it operates (UI, CLI, hardware wallet, cross-chain)
🔐 Security assumptions (online/offline, trusted/untrusted execution)

In Web3, this is essential for:

✅ Designing secure interfaces (signing, governance, minting)

🔐 Ensuring smart contracts only execute under valid usage conditions

🧪 Tailoring security tests to expected vs edge case usage

📜 Providing clear UX & documentation to prevent misuse

📘 1. Types of Context of Use in Web3
Type	Description
User Role Context	End-user, signer, delegate, admin, multisig signer
Interface Context	Browser wallet, mobile app, CLI, DAO dashboard
Security Context	Online vs air-gapped, trusted RPC vs exposed RPC
Chain Context	Mainnet, testnet, L2, bridge domain, cross-chain
Execution Context	Direct call, relayed meta-tx, governance vote, off-chain signature

💥 2. Attack Vectors From Ignoring Context of Use
Vulnerability Type	Risk Description
Improper Role Escalation	Function callable by frontend user not by DAO signer as intended
Meta-tx Signature Confusion	Valid signature replayed outside its original dApp context
Wrong Chain Execution	L2 action replayed on L1 due to lack of domain binding
UI Misrepresentation	Users sign raw data without understanding due to context mismatch
Unintended Usage Surface	Contracts misused via CLI or script outside designed UX/UI

🛡️ 3. Best Practices for Securing Context of Use
Practice	Solidity / Frontend / DevSecOps Implementation
✅ Context-Bound Signature Verification	Use EIP-712 domain separators or chainId, appId, purpose
✅ Role Separation via AccessControl	Limit roles (e.g., SIGNER_ROLE, GOVERNOR_ROLE) to intended context
✅ Interface-Aware UX	Ensure dApp clearly explains intent before signing
✅ Execution Context Logging	Log method of execution (meta-tx, governance, relay)
✅ Fail Closed for Unknown Contexts	Contracts should revert if context is not explicitly defined

✅ 4. Solidity Code: ContextOfUseValidator.sol
This contract:

Validates intended context via domain hash

Prevents signature or input misuse across dApps or chains

Logs context usage for auditing