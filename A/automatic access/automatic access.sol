// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AutomateAccessSuite.sol
/// @notice On-chain analogues of “Automate Access” patterns:
///   Types: Scheduled, OnDemand, EventDriven  
///   AttackTypes: UnauthorizedAutomation, ReplayAttack, Misconfiguration  
///   DefenseTypes: ApprovalWorkflow, RateLimit, AuditLogging, MultiFactor  

enum AutomateAccessType           { Scheduled, OnDemand, EventDriven }
enum AutomateAccessAttackType     { UnauthorizedAutomation, ReplayAttack, Misconfiguration }
enum AutomateAccessDefenseType    { ApprovalWorkflow, RateLimit, AuditLogging, MultiFactor }

error AA__NotOwner();
error AA__TooManyRequests();
error AA__Unauthorized();
error AA__AlreadyApproved();
error AA__NoMFA();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE AUTOMATION (no controls)
///
///    • any caller can trigger access automation → UnauthorizedAutomation
///─────────────────────────────────────────────────────────────────────────────
contract AutomateAccessVuln {
    event AccessAutomated(
        address indexed who,
        uint256 indexed resourceId,
        AutomateAccessType  atype,
        AutomateAccessAttackType attack
    );

    function automateAccess(uint256 resourceId, AutomateAccessType atype) external {
        emit AccessAutomated(msg.sender, resourceId, atype, AutomateAccessAttackType.UnauthorizedAutomation);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB
///
///    • demonstrates unauthorized and replayed automation
///─────────────────────────────────────────────────────────────────────────────
contract Attack_AutomateAccess {
    AutomateAccessVuln public target;
    constructor(AutomateAccessVuln _t) { target = _t; }

    function unauthorized(uint256 resourceId) external {
        target.automateAccess(resourceId, AutomateAccessType.OnDemand);
    }

    function replay(uint256 resourceId) external {
        target.automateAccess(resourceId, AutomateAccessType.OnDemand);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE WITH APPROVAL WORKFLOW
///
///    • Defense: ApprovalWorkflow – owner must approve before automation
///─────────────────────────────────────────────────────────────────────────────
contract AutomateAccessSafeApproval {
    address public owner;
    mapping(uint256 => bool) public approved;

    event AccessAutomated(
        address indexed who,
        uint256 indexed resourceId,
        AutomateAccessType  atype,
        AutomateAccessDefenseType defense
    );

    constructor() { owner = msg.sender; }

    function approve(uint256 resourceId) external {
        if (msg.sender != owner) revert AA__NotOwner();
        approved[resourceId] = true;
    }

    function automateAccess(uint256 resourceId, AutomateAccessType atype) external {
        if (!approved[resourceId]) revert AA__Unauthorized();
        delete approved[resourceId];
        emit AccessAutomated(msg.sender, resourceId, atype, AutomateAccessDefenseType.ApprovalWorkflow);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE WITH RATE LIMITING
///
///    • Defense: RateLimit – cap automations per block per caller
///─────────────────────────────────────────────────────────────────────────────
contract AutomateAccessSafeRateLimit {
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS_PER_BLOCK = 3;

    event AccessAutomated(
        address indexed who,
        uint256 indexed resourceId,
        AutomateAccessType  atype,
        AutomateAccessDefenseType defense
    );

    function automateAccess(uint256 resourceId, AutomateAccessType atype) external {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS_PER_BLOCK) revert AA__TooManyRequests();
        emit AccessAutomated(msg.sender, resourceId, atype, AutomateAccessDefenseType.RateLimit);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 5) SAFE ADVANCED WITH MFA & AUDIT LOGGING
///
///    • Defense: MultiFactor – require MFA before automation  
///               AuditLogging – record every automated access
///─────────────────────────────────────────────────────────────────────────────
contract AutomateAccessSafeAdvanced {
    address public owner;
    mapping(address => bool) public mfaPassed;

    event AuditLog(
        address indexed who,
        uint256 indexed resourceId,
        string             action,
        AutomateAccessDefenseType defense
    );
    event AccessAutomated(
        address indexed who,
        uint256 indexed resourceId,
        AutomateAccessType  atype,
        AutomateAccessDefenseType defense
    );

    error AA__NoMFA();

    constructor() { owner = msg.sender; }

    /// stub MFA: user calls with a token to pass
    function verifyMFA(bytes32 token) external {
        // in practice, validate token properly
        if (token != keccak256(abi.encodePacked(msg.sender))) revert AA__NoMFA();
        mfaPassed[msg.sender] = true;
    }

    function automateAccess(uint256 resourceId, AutomateAccessType atype) external {
        if (!mfaPassed[msg.sender]) revert AA__NoMFA();
        mfaPassed[msg.sender] = false;
        emit AuditLog(msg.sender, resourceId, "automateAccess", AutomateAccessDefenseType.AuditLogging);
        emit AccessAutomated(msg.sender, resourceId, atype, AutomateAccessDefenseType.MultiFactor);
    }
}
