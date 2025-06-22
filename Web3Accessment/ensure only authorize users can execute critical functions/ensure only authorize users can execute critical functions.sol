// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AuthorizationControlSuite.sol
/// @notice On‐chain analogues of “Ensure only authorized users can execute critical functions” patterns:
///   Types: RoleBased, Whitelist, MultiSig, Governance, Timelock  
///   AttackTypes: UnauthorizedAccess, PrivilegeEscalation, Bypass, Replay  
///   DefenseTypes: AccessControl, RoleCheck, RateLimit, SignatureValidation, AuditLogging

enum AuthType             { RoleBased, Whitelist, MultiSig, Governance, Timelock }
enum AuthAttackType       { UnauthorizedAccess, PrivilegeEscalation, Bypass, Replay }
enum AuthDefenseType      { AccessControl, RoleCheck, RateLimit, SignatureValidation, AuditLogging }

error AC__NotOwner();
error AC__NoRole();
error AC__TooManyRequests();
error AC__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE CONTRACT
//    • ❌ no auth: anyone may call criticalFunction → UnauthorizedAccess
////////////////////////////////////////////////////////////////////////////////
contract ACVuln {
    event CriticalExecuted(address indexed who, AuthType atype, AuthAttackType attack);

    function criticalFunction(uint256 data, AuthType atype) external {
        // no authorization check
        emit CriticalExecuted(msg.sender, atype, AuthAttackType.UnauthorizedAccess);
        // ... critical logic ...
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates unauthorized calls, replay attacks
////////////////////////////////////////////////////////////////////////////////
contract Attack_AC {
    ACVuln public target;
    uint256 public lastData;

    constructor(ACVuln _t) {
        target = _t;
    }

    function bypass(uint256 data) external {
        // attacker calls without permission
        target.criticalFunction(data, AuthType.Whitelist);
        lastData = data;
    }

    function replay() external {
        // replay previous call
        target.criticalFunction(lastData, AuthType.RoleBased);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may call
////////////////////////////////////////////////////////////////////////////////
contract ACSafeAccess {
    address public owner;
    event CriticalExecuted(address indexed who, AuthType atype, AuthDefenseType defense);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert AC__NotOwner();
        _;
    }

    function criticalFunction(uint256 data, AuthType atype) external onlyOwner {
        emit CriticalExecuted(msg.sender, atype, AuthDefenseType.AccessControl);
        // ... critical logic ...
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH ROLE CHECK & RATE LIMIT
//    • ✅ Defense: RoleCheck – mapping roles → only addresses with role  
//               RateLimit – cap calls per block
////////////////////////////////////////////////////////////////////////////////
contract ACSafeRoleRate {
    mapping(address => bool)       public hasRole;
    mapping(address => uint256)    public lastBlock;
    mapping(address => uint256)    public callsInBlock;
    uint256 public constant MAX_CALLS = 2;
    event CriticalExecuted(address indexed who, AuthType atype, AuthDefenseType defense);

    error AC__NoRole();
    error AC__TooManyRequests();

    constructor() {
        // grant deploying address the default role
        hasRole[msg.sender] = true;
    }

    function grantRole(address user, bool ok) external {
        // simplistic admin: only existing role holder can grant
        if (!hasRole[msg.sender]) revert AC__NoRole();
        hasRole[user] = ok;
    }

    function criticalFunction(uint256 data, AuthType atype) external {
        if (!hasRole[msg.sender]) revert AC__NoRole();

        // rate-limit per block
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert AC__TooManyRequests();

        emit CriticalExecuted(msg.sender, atype, AuthDefenseType.RoleCheck);
        // ... critical logic ...
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & AUDIT LOGGING
//    • ✅ Defense: SignatureValidation – require off‐chain signed payload  
//               AuditLogging       – record every exec
////////////////////////////////////////////////////////////////////////////////
contract ACSafeAdvanced {
    address public signer;
    event CriticalExecuted(address indexed who, AuthType atype, AuthDefenseType defense);
    event AuditLog(address indexed who, uint256 data, AuthDefenseType defense);
    error AC__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function criticalFunction(
        uint256 data,
        AuthType atype,
        bytes calldata sig
    ) external {
        // verify signature over (msg.sender||data||atype)
        bytes32 h = keccak256(abi.encodePacked(msg.sender, data, atype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert AC__InvalidSignature();

        emit CriticalExecuted(msg.sender, atype, AuthDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, data, AuthDefenseType.AuditLogging);
        // ... critical logic ...
    }
}
