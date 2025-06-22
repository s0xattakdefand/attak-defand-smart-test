🔐 Access Control Testing in Smart Contracts
Access Control Testing verifies that only authorized users/roles can call sensitive functions — and unauthorized access is consistently rejected across all paths (including fallback, delegatecall, and upgrade scenarios).

Access control failures are among the most exploited vulnerabilities in smart contracts — leading to admin takeovers, treasury drains, and governance hijacking.

✅ Types of Access Control Testing
#	Type	Description
1	Role Enforcement Test	Ensure only specified roles (owner, admin) can call protected functions.
2	Unauthorized Rejection Test	Ensure unprivileged callers always revert.
3	Role Drift Test	Test whether roles change unintentionally across time, calls, or upgrades.
4	Storage Collision Role Bypass Test	Ensure roles aren’t overwritten via proxy or delegatecall storage drift.
5	Fallback Access Test	Ensure fallback function doesn’t route privileged logic to unprivileged callers.
6	Signature Role Test	Verify that MetaTx or permit() is signed by proper role-holder.
7	Upgrade Access Test	Ensure only authorized callers can trigger upgrade or proxy admin functions.
8	Cross-Contract Call Access Test	Test that only whitelisted contracts can trigger privileged logic.
9	Time-Locked Access Test	Ensure access is granted only after delay or time window.
10	Interface Spoofing Test	Prevent contracts from spoofing role via fake interface return values.

⚔️ Common Attack Vectors Caught
Bug	Description
Role Not Enforced	Admin-only function callable by any address
Delegatecall Role Drift	Logic contract has owner, but proxy overwrites it
Signature Replay	Attacker reuses valid signature to impersonate role
Proxy Upgrade by Any	upgradeTo() lacks role checks
MetaTx Forgery	Malicious relayer replays a role-signed payload
Fallback Trap	Function not declared, routes to fallback with no role check

🛡️ Best Practice Defenses
Strategy	Description
onlyOwner, hasRole()	Explicit modifier usage for protected logic
Role Registry	Use AccessControl, Ownable, or custom mapping
MetaTx Signature Guard	Include nonce, domain separator, and expiration
Storage Layout Lock	Freeze role slots in upgradeable layout
Selector Filtering	Allow only known selectors to execute via fallback
Role Replay Guard	Log and block reused role-based payloads