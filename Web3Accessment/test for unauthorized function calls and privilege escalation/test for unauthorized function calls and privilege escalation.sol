// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title UnauthorizedCallPrivilegeEscalationSuite.sol
/// @notice Patterns to test for unauthorized function calls and privilege escalation:
///   Types: DirectCall, FallbackCall, LowLevelCall, DelegateCall, Upgrade  
///   AttackTypes: UnauthorizedCall, PrivilegeEscalation, Bypass, DelegateHijack  
///   DefenseTypes: AccessControl, RoleCheck, CEI, SignatureValidation, RateLimit

enum UCPType             { DirectCall, FallbackCall, LowLevelCall, DelegateCall, Upgrade }
enum UCPAttackType       { UnauthorizedCall, PrivilegeEscalation, Bypass, DelegateHijack }
enum UCPDefenseType      { AccessControl, RoleCheck, CEI, SignatureValidation, RateLimit }

error UCP__NotOwner();
error UCP__NoRole();
error UCP__Reentrant();
error UCP__TooManyRequests();
error UCP__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE CONTRACT
//    • ❌ no checks: anyone may call adminFunction → UnauthorizedCall
////////////////////////////////////////////////////////////////////////////////
contract UCPVuln {
    address public owner;
    uint public secret;

    constructor() { owner = msg.sender; }

    // critical admin function
    function adminFunction(uint newSecret, UCPType dtype) external {
        secret = newSecret;
        // no access check
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates unauthorized direct calls and delegatecall hijack
////////////////////////////////////////////////////////////////////////////////
contract Attack_UCP {
    UCPVuln public target;
    uint public lastSecret;

    constructor(UCPVuln _t) { target = _t; }

    function unauthorized(uint x) external {
        // attacker calls without permission
        target.adminFunction(x, UCPType.DirectCall);
        lastSecret = x;
    }

    function replay() external {
        target.adminFunction(lastSecret, UCPType.DirectCall);
    }

    function delegateHijack(address impl, uint x) external {
        // hijack via delegatecall
        (bool ok,) = address(target).delegatecall(
            abi.encodeWithSelector(UCPVuln.adminFunction.selector, x, UCPType.DelegateCall)
        );
        require(ok);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL (OWNER ONLY)
//    • ✅ Defense: AccessControl – only owner may call adminFunction
////////////////////////////////////////////////////////////////////////////////
contract UCPSafeAccess {
    address public owner;
    uint public secret;
    event AdminCalled(address indexed who, uint newSecret, UCPDefenseType defense);

    constructor() { owner = msg.sender; }

    modifier onlyOwner() {
        if (msg.sender != owner) revert UCP__NotOwner();
        _;
    }

    function adminFunction(uint newSecret, UCPType dtype) external onlyOwner {
        secret = newSecret;
        emit AdminCalled(msg.sender, newSecret, UCPDefenseType.AccessControl);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH ROLE CHECK & RATE LIMIT
//    • ✅ Defense: RoleCheck – only addresses with ROLE_ADMIN  
//               RateLimit – cap calls per block
////////////////////////////////////////////////////////////////////////////////
contract UCPSafeRoleRate {
    mapping(address => bool) public isAdmin;
    mapping(address => uint) public lastBlock;
    mapping(address => uint) public callsInBlock;
    uint public secret;
    uint constant MAX_CALLS = 2;
    event AdminCalled(address indexed who, uint newSecret, UCPDefenseType defense);

    error UCP__NoRole();
    error UCP__TooManyRequests();

    constructor() {
        isAdmin[msg.sender] = true;
    }

    function grantRole(address user, bool ok) external {
        if (!isAdmin[msg.sender]) revert UCP__NoRole();
        isAdmin[user] = ok;
    }

    function adminFunction(uint newSecret, UCPType dtype) external {
        if (!isAdmin[msg.sender]) revert UCP__NoRole();
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert UCP__TooManyRequests();

        secret = newSecret;
        emit AdminCalled(msg.sender, newSecret, UCPDefenseType.RoleCheck);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE WITH CEI & SIGNATURE VALIDATION
//    • ✅ Defense: CEI – update state before external interactions  
//               SignatureValidation – require off‐chain signed payload
////////////////////////////////////////////////////////////////////////////////
contract UCPSafeAdvanced {
    address public owner;
    address public signer;
    uint public secret;
    event AdminCalled(address indexed who, uint newSecret, UCPDefenseType defense);

    error UCP__InvalidSignature();
    error UCP__Reentrant();

    bool private _entered;
    modifier noReentry() {
        if (_entered) revert UCP__Reentrant();
        _entered = true;
        _;
        _entered = false;
    }

    constructor(address _signer) {
        owner = msg.sender;
        signer = _signer;
    }

    function adminFunction(
        uint newSecret,
        UCPType dtype,
        bytes calldata sig
    ) external noReentry {
        // verify signature over (msg.sender||newSecret||dtype)
        bytes32 h = keccak256(abi.encodePacked(msg.sender, newSecret, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert UCP__InvalidSignature();

        // CEI: effects
        secret = newSecret;

        emit AdminCalled(msg.sender, newSecret, UCPDefenseType.SignatureValidation);
        // ... no external calls here ...
    }
}
