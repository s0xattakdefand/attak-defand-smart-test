// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title CrossAgencyPrioritySuite.sol
/// @notice On‐chain analogues of “Cross Agency Priority” coordination patterns:
///   Types: StrategicPlan, OperationalTask, ComplianceReview, ResourceAllocation  
///   AttackTypes: PriorityHijacking, DataTampering, UnauthorizedAssignment, DenialOfService  
///   DefenseTypes: AccessControl, Validation, MultiAgencyApproval, RateLimit, AuditLogging

enum CrossAgencyPriorityType       { StrategicPlan, OperationalTask, ComplianceReview, ResourceAllocation }
enum CAPAttackType                 { PriorityHijacking, DataTampering, UnauthorizedAssignment, DenialOfService }
enum CAPDefenseType                { AccessControl, Validation, MultiAgencyApproval, RateLimit, AuditLogging }

error CAP__NotAuthorized();
error CAP__InvalidPriority();
error CAP__TooManyRequests();
error CAP__NotApproved();
error CAP__AlreadyApproved();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE PRIORITY MANAGER
//    • ❌ no checks: anyone may set or override priorities → PriorityHijacking
////////////////////////////////////////////////////////////////////////////////
contract CrossAgencyPriorityVuln {
    mapping(uint256 => uint256) public priority;  // itemId → priority

    event PrioritySet(
        address indexed who,
        uint256                itemId,
        CrossAgencyPriorityType ptype,
        uint256                value,
        CAPAttackType          attack
    );

    function setPriority(
        uint256 itemId,
        CrossAgencyPriorityType ptype,
        uint256 value
    ) external {
        priority[itemId] = value;
        emit PrioritySet(msg.sender, itemId, ptype, value, CAPAttackType.PriorityHijacking);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates hijacking, tampering, unauthorized assignment, DoS
////////////////////////////////////////////////////////////////////////////////
contract Attack_CrossAgencyPriority {
    CrossAgencyPriorityVuln public target;

    constructor(CrossAgencyPriorityVuln _t) {
        target = _t;
    }

    function hijack(uint256 itemId, uint256 newPriority) external {
        target.setPriority(itemId, CrossAgencyPriorityType.StrategicPlan, newPriority);
    }

    function tamper(uint256 itemId, uint256 bogusPriority) external {
        target.setPriority(itemId, CrossAgencyPriorityType.OperationalTask, bogusPriority);
    }

    function replayHijack(uint256 itemId, uint256 value) external {
        target.setPriority(itemId, CrossAgencyPriorityType.StrategicPlan, value);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may set priorities
////////////////////////////////////////////////////////////////////////////////
contract CrossAgencyPrioritySafeAccess {
    mapping(uint256 => uint256) public priority;
    address public owner;

    event PrioritySet(
        address indexed who,
        uint256                itemId,
        CrossAgencyPriorityType ptype,
        uint256                value,
        CAPDefenseType         defense
    );

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert CAP__NotAuthorized();
        _;
    }

    function setPriority(
        uint256 itemId,
        CrossAgencyPriorityType ptype,
        uint256 value
    ) external onlyOwner {
        priority[itemId] = value;
        emit PrioritySet(msg.sender, itemId, ptype, value, CAPDefenseType.AccessControl);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH VALIDATION & RATE LIMIT
//    • ✅ Defense: Validation – priority ∈ [1,10]  
//               RateLimit – cap calls per block
////////////////////////////////////////////////////////////////////////////////
contract CrossAgencyPrioritySafeValidate {
    mapping(uint256 => uint256) public priority;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MIN_PRI = 1;
    uint256 public constant MAX_PRI = 10;
    uint256 public constant MAX_CALLS = 5;

    event PrioritySet(
        address indexed who,
        uint256                itemId,
        CrossAgencyPriorityType ptype,
        uint256                value,
        CAPDefenseType         defense
    );

    function setPriority(
        uint256 itemId,
        CrossAgencyPriorityType ptype,
        uint256 value
    ) external {
        if (value < MIN_PRI || value > MAX_PRI) revert CAP__InvalidPriority();

        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert CAP__TooManyRequests();

        priority[itemId] = value;
        emit PrioritySet(msg.sender, itemId, ptype, value, CAPDefenseType.Validation);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH MULTI‐AGENCY APPROVAL & AUDIT LOGGING
//    • ✅ Defense: MultiAgencyApproval – require ≥ threshold approvals  
//               AuditLogging       – record final commit
////////////////////////////////////////////////////////////////////////////////
contract CrossAgencyPrioritySafeAdvanced {
    mapping(uint256 => uint256) public priority;
    mapping(uint256 => mapping(address => bool)) public approved;
    mapping(uint256 => uint256) public approvalCount;
    uint256 public constant THRESHOLD = 2;

    event Approved(
        address indexed who,
        uint256                itemId,
        CrossAgencyPriorityType ptype,
        uint256                value,
        CAPDefenseType         defense
    );
    event PriorityCommitted(
        address indexed who,
        uint256                itemId,
        CrossAgencyPriorityType ptype,
        uint256                value,
        CAPDefenseType         defense
    );

    error CAP__NotApproved();
    error CAP__AlreadyApproved();

    function proposePriority(
        uint256 itemId,
        CrossAgencyPriorityType ptype,
        uint256 value
    ) external {
        // each approver ticks
        if (approved[itemId][msg.sender]) revert CAP__AlreadyApproved();
        approved[itemId][msg.sender] = true;
        approvalCount[itemId]++;
        emit Approved(msg.sender, itemId, ptype, value, CAPDefenseType.MultiAgencyApproval);

        if (approvalCount[itemId] >= THRESHOLD) {
            priority[itemId] = value;
            emit PriorityCommitted(msg.sender, itemId, ptype, value, CAPDefenseType.MultiAgencyApproval);
        }
    }
}
