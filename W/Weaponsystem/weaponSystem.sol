// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WeaponSystemSuite.sol
/// @notice On‐chain analogues of “Weapon System” control patterns:
///   Types: Offensive, Defensive, Stealth, Autonomous  
///   AttackTypes: Spoofing, SupplyChainCompromise, DenialOfService, CyberAttack  
///   DefenseTypes: Authentication, Encryption, Redundancy, RateLimit

enum WeaponSystemType          { Offensive, Defensive, Stealth, Autonomous }
enum WeaponSystemAttackType    { Spoofing, SupplyChainCompromise, DenialOfService, CyberAttack }
enum WeaponSystemDefenseType   { Authentication, Encryption, Redundancy, RateLimit }

error WS__Unauthorized();
error WS__InvalidSignature();
error WS__TooManyRequests();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE WEAPON SYSTEM
//    • ❌ no access control: anyone may issue commands → Spoofing
////////////////////////////////////////////////////////////////////////////////
contract WeaponSystemVuln {
    mapping(uint256 => bool) public armed;
    event CommandIssued(
        address indexed who,
        uint256           systemId,
        WeaponSystemType  wtype,
        bool              arm,
        WeaponSystemAttackType attack
    );

    function issueCommand(uint256 systemId, WeaponSystemType wtype, bool arm) external {
        armed[systemId] = arm;
        emit CommandIssued(msg.sender, systemId, wtype, arm, WeaponSystemAttackType.Spoofing);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates spoofed commands & replay
////////////////////////////////////////////////////////////////////////////////
contract Attack_WeaponSystem {
    WeaponSystemVuln public target;
    uint256 public lastSystem;
    bool public lastState;

    constructor(WeaponSystemVuln _t) { target = _t; }

    function spoof(uint256 systemId, bool arm) external {
        target.issueCommand(systemId, WeaponSystemType.Offensive, arm);
        lastSystem = systemId;
        lastState = arm;
    }

    function replay() external {
        target.issueCommand(lastSystem, WeaponSystemType.Offensive, lastState);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH AUTHENTICATION
//    • ✅ Defense: Authentication – only owner may issue
////////////////////////////////////////////////////////////////////////////////
contract WeaponSystemSafeAuth {
    mapping(uint256 => bool) public armed;
    address public owner;
    event CommandIssued(
        address indexed who,
        uint256           systemId,
        WeaponSystemType  wtype,
        bool              arm,
        WeaponSystemDefenseType defense
    );
    error WS__Unauthorized();

    constructor() { owner = msg.sender; }

    function issueCommand(uint256 systemId, WeaponSystemType wtype, bool arm) external {
        if (msg.sender != owner) revert WS__Unauthorized();
        armed[systemId] = arm;
        emit CommandIssued(msg.sender, systemId, wtype, arm, WeaponSystemDefenseType.Authentication);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH ENCRYPTION
//    • ✅ Defense: Encryption – require valid signature over payload
////////////////////////////////////////////////////////////////////////////////
contract WeaponSystemSafeEncryption {
    mapping(uint256 => bool) public armed;
    address public signer;
    event CommandIssued(
        address indexed who,
        uint256           systemId,
        WeaponSystemType  wtype,
        bool              arm,
        WeaponSystemDefenseType defense
    );
    error WS__InvalidSignature();

    constructor(address _signer) { signer = _signer; }

    function issueEncryptedCommand(
        uint256 systemId,
        WeaponSystemType wtype,
        bool arm,
        bytes calldata sig
    ) external {
        bytes32 payload = keccak256(abi.encodePacked(systemId, wtype, arm));
        bytes32 ethMsg  = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", payload));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(ethMsg, v, r, s) != signer) revert WS__InvalidSignature();
        armed[systemId] = arm;
        emit CommandIssued(msg.sender, systemId, wtype, arm, WeaponSystemDefenseType.Encryption);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH REDUNDANCY & RATE LIMIT
//    • ✅ Defense: Redundancy – multi‐approval before arming  
//               RateLimit – cap commands per block
////////////////////////////////////////////////////////////////////////////////
contract WeaponSystemSafeAdvanced {
    mapping(uint256 => mapping(address => bool)) public approvals;
    mapping(uint256 => uint256) public approvalCount;
    mapping(uint256 => bool) public armed;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;

    address[] public controllers;
    uint256 public required;
    uint256 public constant MAX_CALLS = 3;

    event CommandApproved(
        uint256 indexed systemId,
        address indexed who,
        uint256          approvals,
        WeaponSystemDefenseType defense
    );
    event CommandExecuted(
        uint256 indexed systemId,
        bool              arm,
        WeaponSystemDefenseType defense
    );

    error WS__Unauthorized();
    error WS__TooManyRequests();

    constructor(address[] memory _controllers, uint256 _required) {
        controllers = _controllers;
        required = _required;
    }

    function isController(address who) internal view returns (bool) {
        for (uint i; i < controllers.length; i++) {
            if (controllers[i] == who) return true;
        }
        return false;
    }

    function approveCommand(uint256 systemId) external {
        if (!isController(msg.sender)) revert WS__Unauthorized();
        if (!approvals[systemId][msg.sender]) {
            approvals[systemId][msg.sender] = true;
            approvalCount[systemId]++;
            emit CommandApproved(systemId, msg.sender, approvalCount[systemId], WeaponSystemDefenseType.Redundancy);
        }
        if (approvalCount[systemId] >= required && !armed[systemId]) {
            armed[systemId] = true;
            emit CommandExecuted(systemId, true, WeaponSystemDefenseType.Redundancy);
        }
    }

    function issueCommand(uint256 systemId, bool arm) external {
        // rate-limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert WS__TooManyRequests();
        if (!isController(msg.sender)) revert WS__Unauthorized();

        armed[systemId] = arm;
        emit CommandExecuted(systemId, arm, WeaponSystemDefenseType.RateLimit);
    }
}
