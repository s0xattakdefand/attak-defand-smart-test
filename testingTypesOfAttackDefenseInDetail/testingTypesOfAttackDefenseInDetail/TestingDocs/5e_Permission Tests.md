🔐 Permission Tests in Smart Contracts
Permission Testing verifies that only authorized roles, addresses, or contracts can execute specific functions or access protected resources. It ensures correct access control, role enforcement, and modifiers are applied and behaving exactly as intended.

🔒 Without proper permission tests, attackers may gain unauthorized access to admin-only logic, funds, upgrades, or sensitive operations.

✅ Types of Permission Tests
#	Type	Description
1	Owner-Only Access Test	Verify that only the owner can call onlyOwner functions.
2	Role-Based Access Test	Validate access control using hasRole() from OpenZeppelin AccessControl.
3	MultiSig / Admin Tests	Confirm only configured multisig or DAO contracts can execute privileged logic.
4	Deployer Access Test	Ensure only contract deployer or initializer has setup rights.
5	Cross-Contract Caller Validation	Test access based on msg.sender == trustedContract.
6	Fallback Access Test	Ensure fallback logic doesn’t allow bypassed permissioned logic.
7	Proxy Upgrade Admin Test	Confirm only proxy admin or UUPS owner can upgrade logic.
8	Restricted Receiver Test	Check that only whitelisted addresses can receive funds or data.
9	MetaTx Signer Check	Test that only valid signer from off-chain payload is respected.
10	Revoke / Renounce Permission Test	Validate behavior when roles are revoked or renounced.

⚔️ Attack Types Caught by Permission Tests
Attack Type	Description
Admin Access Bypass	msg.sender not validated before upgrade or sweep.
Zero Address Role	Role granted to address(0) is left unguarded.
Proxy Ownership Drift	Proxy admin transferred without reassigning control logic.
Fallback Execution Bypass	Logic accessed via fallback route without modifier.
DAO Proposal Re-entry	Proposal executes logic that only DAO should trigger.
Role Replay Drift	MetaTx or signature used to impersonate authorized role.
Self-Grant Role Injection	Contract grants itself a role without audit trail.
Public Modifier Removal	Modifier removed in upgrade, permissions dropped silently.
Revoke Path Failure	Role is revoked but logic still accessible.
Misconfigured TrustedCaller	msg.sender comparison points to outdated or incorrect contract.

🛡️ Defense Types Validated by Permission Tests
Defense Type	Description
✅ AccessControl / Ownable Enforcement	Confirms modifiers protect privileged logic.
✅ Proxy Admin Lock	Prevents proxy upgrade drift via EIP-1967 or UUPS.
✅ Permission Revert Coverage	Ensures unauthorized access fails explicitly.
✅ Trusted Contract Binding	Only known msg.sender allowed for cross-calls.
✅ MetaTx / Signature Binding	Signer address must match expected permission scope.
✅ Zero Role Defense	Role must be assigned only to valid EOA or contract.
✅ Granular Modifier Enforcement	Tests multiple access layers (onlyOwner, onlyAdmin, etc.).
✅ Pause / Timelock Controls	Tests that protected logic is gated when paused or pending.
✅ Upgradeable Permission Lock	Tests that upgrades don’t erase role logic.
✅ Fallback Permission Binding	Prevents fallback from exposing privileged paths.