🪂 Fallback Testing in Smart Contracts
Fallback Testing verifies that a contract’s fallback() or receive() function behaves securely, predictably, and resists exploitation from:

🧟 zombie selectors

🔁 drifted calldata

🧨 hidden delegatecalls

🦠 proxy misroutes

The fallback function is often the most dangerous surface — it’s executed when:

an undefined selector is called

raw ETH is sent

a proxy delegates unknown functions

✅ Types of Fallback Testing
#	Type	Description
1	Selector Fuzzing Test	Send random 4-byte msg.sig values and validate fallback response.
2	Receive ETH Test	Send ETH directly to test receive() safety and trigger behavior.
3	Fallback Route Test	Route unknown selectors to delegatecall, ensure only whitelisted logic runs.
4	Zombie Selector Trigger Test	Use legacy or removed function selectors to test ghost logic.
5	Event Drift Fallback Test	Confirm fallback doesn’t emit fake/logically-invalid events.
6	Access Control in Fallback	Ensure fallback cannot mutate state without roles or permissions.
7	Gas Bomb in Fallback	Ensure fallback rejects large calldata or infinite loops.
8	Storage Write Guard Test	Confirm fallback does not mutate storage unless explicitly allowed.
9	Upgrade Drift Fallback Test	Fallback shouldn’t become attack vector post-upgrade.
10	Multicall Selector Drift Test	Batch calls with invalid selectors shouldn’t silently succeed.

⚔️ Fallback Attack Types
Type	Description
Zombie Selector Attack	Call undeclared selector that reactivates old logic via fallback.
Delegatecall Exploit via Fallback	Fallback routes to attacker’s logic contract via open delegatecall.
Proxy Storage Drift	Fallback uses storage from wrong context due to layout mismatch.
Gas Grief Fallback	Send large calldata or loops to cause denial-of-service via fallback.
Fallback Permission Bypass	Fallback triggers privileged logic without access control.
Receive Function Exploit	ETH sent to contract triggers malicious state changes or logic.
Fallback Emit Spoofing	Fallback emits events to mislead indexers or off-chain listeners.

🛡️ Fallback Defense Types
Type	Description
✅ Selector Whitelist	Maintain list of approved function selectors.
✅ Fallback Signature Registry	Compare msg.sig to known hash and reject unknowns.
✅ Fallback Access Control	Require caller to hold role before executing logic via fallback.
✅ Calldata Length Check	Reject non-zero calldata of invalid size.
✅ Gas Cap in Fallback	Limit fallback execution gas to prevent grief loops.
✅ Delegatecall Route Guard	Ensure delegatecall routes only to trusted targets.
✅ Receive() Guard	receive() only allows ETH, no code paths.
✅ Storage Access Restriction	Prevent fallback from writing to sensitive state.