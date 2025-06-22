// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title UserContingencyPlanSuite.sol
/// @notice On‑chain analogues of “User Contingency Plan” patterns:
///   Types: Recovery, Backup, Failover  
///   AttackTypes: PlanIgnorance, SinglePointFailure, Tampering  
///   DefenseTypes: ImmutableOnce, MultiApproval, ScheduledTest  

enum ContingencyPlanType    { Recovery, Backup, Failover }
enum ContingencyAttackType  { PlanIgnorance, SinglePointFailure, Tampering }
enum ContingencyDefenseType { ImmutableOnce, MultiApproval, ScheduledTest }

error CP__NotOwner();
error CP__AlreadySet();
error CP__NotApprover();
error CP__InsufficientApprovals();
error CP__TestOutOfDate();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE CONTINGENCY PLAN STORE
///
///    • anyone may set or overwrite any plan  
///    • Attack: Tampering  
///─────────────────────────────────────────────────────────────────────────────
contract ContingencyPlanVuln {
    mapping(uint256 => string) public plans;
    event PlanSet(uint256 indexed id, ContingencyPlanType kind, string desc, ContingencyAttackType attack);

    function setPlan(uint256 id, ContingencyPlanType kind, string calldata desc) external {
        plans[id] = desc;
        emit PlanSet(id, kind, desc, ContingencyAttackType.Tampering);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB: ignore or tamper with plan
///
///    • PlanIgnorance: never call setPlan  
///    • Tampering: overwrite existing plan  
///─────────────────────────────────────────────────────────────────────────────
contract Attack_ContingencyPlan {
    ContingencyPlanVuln public target;
    constructor(ContingencyPlanVuln _t) { target = _t; }

    function ignore(uint256 id, ContingencyPlanType kind) external view returns (string memory) {
        // attacker never sets or tests plan → ignorance
        return target.plans(id);
    }

    function tamper(uint256 id, ContingencyPlanType kind, string calldata newDesc) external {
        target.setPlan(id, kind, newDesc);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE STORE (IMMUTABLE ONCE)
///
///    • Defense: only owner may set, only once per plan  
///─────────────────────────────────────────────────────────────────────────────
contract ContingencyPlanSafe {
    address public owner;
    mapping(uint256 => string) public plans;
    mapping(uint256 => bool)  private _set;
    event PlanLogged(uint256 indexed id, ContingencyPlanType kind, string desc, ContingencyDefenseType defense);

    constructor() {
        owner = msg.sender;
    }

    function setPlan(uint256 id, ContingencyPlanType kind, string calldata desc) external {
        if (msg.sender != owner) revert CP__NotOwner();
        if (_set[id])              revert CP__AlreadySet();
        _set[id] = true;
        plans[id] = desc;
        emit PlanLogged(id, kind, desc, ContingencyDefenseType.ImmutableOnce);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) MULTI‑APPROVAL + SCHEDULED TEST
///
///    • Defense: require N-of-M approvals and periodic testing  
///─────────────────────────────────────────────────────────────────────────────
contract ContingencyPlanSafeAdvanced {
    address public owner;
    uint256 public testInterval; // seconds
    mapping(address => bool)             public approvers;
    address[]                            public approverList;
    uint256                              public requiredApprovals;
    struct Plan { string desc; uint256 approvals; mapping(address=>bool) voted; uint256 lastTest; }
    mapping(uint256 => Plan) private _plans;

    event PlanProposed(uint256 indexed id, string desc);
    event PlanApproved(uint256 indexed id, address approver);
    event PlanActivated(uint256 indexed id, ContingencyDefenseType defense);
    event PlanTested(uint256 indexed id, uint256 timestamp, ContingencyDefenseType defense);

    error CP__NotApprover();
    error CP__AlreadyVoted();
    error CP__InsufficientApprovals();
    error CP__TestOutOfDate();

    constructor(address[] memory _approvers, uint256 _requiredApprovals, uint256 _testInterval) {
        owner             = msg.sender;
        testInterval      = _testInterval;
        requiredApprovals = _requiredApprovals;
        for (uint i; i < _approvers.length; i++) {
            approvers[_approvers[i]] = true;
            approverList.push(_approvers[i]);
        }
    }

    /// propose a new plan (owner only)
    function proposePlan(uint256 id, string calldata desc) external {
        if (msg.sender != owner) revert CP__NotOwner();
        Plan storage p = _plans[id];
        p.desc = desc;
        p.approvals = 0;
        p.lastTest = block.timestamp;
        emit PlanProposed(id, desc);
    }

    /// approvers cast votes
    function approvePlan(uint256 id) external {
        if (!approvers[msg.sender]) revert CP__NotApprover();
        Plan storage p = _plans[id];
        if (p.voted[msg.sender]) revert CP__AlreadyVoted();
        p.voted[msg.sender] = true;
        p.approvals++;
        emit PlanApproved(id, msg.sender);
    }

    /// activate plan once enough approvals
    function activatePlan(uint256 id) external {
        Plan storage p = _plans[id];
        if (p.approvals < requiredApprovals) revert CP__InsufficientApprovals();
        emit PlanActivated(id, ContingencyDefenseType.MultiApproval);
    }

    /// scheduled test to ensure plan is fresh
    function testPlan(uint256 id) external {
        Plan storage p = _plans[id];
        if (block.timestamp > p.lastTest + testInterval) revert CP__TestOutOfDate();
        p.lastTest = block.timestamp;
        emit PlanTested(id, block.timestamp, ContingencyDefenseType.ScheduledTest);
    }

    /// view plan description
    function getPlan(uint256 id) external view returns (string memory) {
        return _plans[id].desc;
    }
}
