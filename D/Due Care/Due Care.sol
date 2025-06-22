// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DueCareSuite.sol
/// @notice On‑chain analogues of “Due Care” governance patterns:
///   Types: Standard, Enhanced, Reasonable, Strict  
///   AttackTypes: Negligence, Omission, BreachDuty  
///   DefenseTypes: PolicyEnforcement, Training, Monitoring, ComplianceAudit  

enum DueCareType          { Standard, Enhanced, Reasonable, Strict }
enum DueCareAttackType    { Negligence, Omission, BreachDuty }
enum DueCareDefenseType   { PolicyEnforcement, Training, Monitoring, ComplianceAudit }

error DC__NotOwner();
error DC__NotTrained();
error DC__TooFrequent();
error DC__NotAllowed();
error DC__AlreadyPerformed();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE PROCESS (no care checks)
//    • anyone may perform any action at any time → Negligence
////////////////////////////////////////////////////////////////////////////////
contract DueCareVuln {
    event ActionPerformed(
        address indexed who,
        uint256 indexed id,
        DueCareType      dtype,
        DueCareAttackType attack
    );

    /// ❌ no governance: free‑for‑all action
    function performAction(uint256 id, DueCareType dtype) external {
        emit ActionPerformed(msg.sender, id, dtype, DueCareAttackType.Negligence);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • demonstrates negligent bulk actions and omissions
////////////////////////////////////////////////////////////////////////////////
contract Attack_DueCare {
    DueCareVuln public target;
    constructor(DueCareVuln _t) { target = _t; }

    /// flood actions without regard to care level
    function floodActions(uint256[] calldata ids, DueCareType dtype) external {
        for (uint i = 0; i < ids.length; i++) {
            target.performAction(ids[i], dtype);
        }
    }

    /// skip required action → omission
    function omitAction(uint256 id) external {
        // simply does nothing, representing omission
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE PROCESS WITH POLICY ENFORCEMENT
//    • only owner may perform, one‑time per id → PolicyEnforcement
////////////////////////////////////////////////////////////////////////////////
contract DueCareSafe {
    mapping(uint256 => bool)    private _done;
    address public owner;
    event ActionLogged(
        uint256 indexed id,
        DueCareType      dtype,
        DueCareDefenseType defense
    );

    constructor() {
        owner = msg.sender;
    }

    /// ✅ owner must explicitly perform each action once
    function performAction(uint256 id, DueCareType dtype) external {
        if (msg.sender != owner)       revert DC__NotOwner();
        if (_done[id])                 revert DC__AlreadyPerformed();
        _done[id] = true;
        emit ActionLogged(id, dtype, DueCareDefenseType.PolicyEnforcement);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE ADVANCED WITH TRAINING, MONITORING & AUDIT
//    • Defense: require training, rate‑limit, audit logs → Training, Monitoring, ComplianceAudit
////////////////////////////////////////////////////////////////////////////////
contract DueCareSafeAdvanced {
    mapping(address => bool)    public trained;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public countInBlock;
    mapping(uint256 => bool)    private _done;
    address public owner;
    uint256 public constant MAX_PER_BLOCK = 5;

    event ActionLogged(
        address indexed who,
        uint256 indexed id,
        DueCareType      dtype,
        DueCareDefenseType defense
    );
    event Audit(
        address indexed who,
        uint256 indexed id,
        string           note,
        DueCareDefenseType defense
    );

    error DC__NotTrained();
    error DC__TooFrequent();

    constructor() {
        owner = msg.sender;
    }

    /// owner may train participants
    function setTrained(address who, bool ok) external {
        require(msg.sender == owner, "only owner");
        trained[who] = ok;
    }

    /// trained participants perform actions, rate‑limited per block
    function performAction(uint256 id, DueCareType dtype) external {
        if (!trained[msg.sender]) revert DC__NotTrained();

        // rate‑limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_PER_BLOCK) revert DC__TooFrequent();

        require(!_done[id], "already done");
        _done[id] = true;
        emit ActionLogged(msg.sender, id, dtype, DueCareDefenseType.Training);
        emit Audit(msg.sender, id, "action performed under due care", DueCareDefenseType.ComplianceAudit);
    }

    /// monitoring function: owner may review and flag omissions
    function auditOmission(address who, uint256 id, string calldata note) external {
        require(msg.sender == owner, "only owner");
        if (!_done[id]) {
            emit Audit(who, id, note, DueCareDefenseType.Monitoring);
        }
    }
}
