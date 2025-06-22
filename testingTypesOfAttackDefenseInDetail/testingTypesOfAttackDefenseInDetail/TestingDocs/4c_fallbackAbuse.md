⚠️ Fallback Abuse in Smart Contracts
Fallback abuse occurs when attackers exploit the fallback() or receive() function of a contract to:

Bypass function logic

Trigger hidden or dangerous behavior

Execute logic through unknown selectors

Interfere with proxy or delegatecall systems

Fallbacks are entry points of uncertainty — and if not locked down, they become backdoors, gas bombs, or reentrancy vectors.

✅ Types of Fallback Abuse
#	Type	Description
1	Unauthorized Fallback Execution	Attackers trigger fallback logic that should only be accessible to specific roles.
2	Selector Drift Abuse	Undefined function selectors route to fallback, allowing execution of dangerous paths.
3	Gas Bomb in Fallback	Fallback performs storage writes or loops — causing gas denial-of-service.
4	Delegatecall Fallback Trap	Proxy or logic contract routes to fallback and executes malicious storage-modifying logic.
5	Silent Receive Trap	receive() silently absorbs ETH and emits no events, hiding internal activity.
6	Multicall Fallback Exploit	multicall() to fallback causes batch logic to run unintendedly.
7	Proxy Implementation Drift	Implementation contract’s fallback overrides expected proxy behavior.
8	Constructor-Era Fallback Exploit	Fallback triggered during contract construction or via create2.
9	Cross-Chain Fallback Trigger	Fallback invoked by cross-chain router that sends unexpected calldata.
10	Token Hook Fallback Execution	Tokens calling fallback via transferAndCall, onERC721Received, or approve() side effects.

⚔️ Attack Scenarios
Type	Exploit
Selector Drift	Call unknown selector 0xdeadbeef, fallback routes to selfdestruct()
Delegatecall Fallback	Proxy calls fallback which mutates proxy storage via logic contract
Gas Bomb	Call fallback with storage loops, cause tx to run out of gas
Silent Receive	Send ETH to trigger receive(), modify internal state with no trace
Multicall	Craft batch of unknown function selectors, route all to fallback logic

🛡️ Defense Techniques
Type	Defense
Fallback Access Guard	Add require(msg.sender == owner) inside fallback
Selector Registry	Validate msg.sig inside fallback and block unknown selectors
Revert Fallback	Default fallback should revert() unless explicitly required
Receive Guard	Prevent state-changing logic in receive()
Fallback Logging	Emit events from fallback to ensure visibility
Delegatecall Trap Guard	Use isContract() and implementationCheck before fallback delegatecall
Multicall Selector Filtering	Allow only registered selectors in fallback multicalls