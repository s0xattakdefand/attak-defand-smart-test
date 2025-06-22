// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WorkingGroupSuite.sol
/// @notice On‐chain analogues of “Working Group” governance patterns:
///   Types: Editorial, Steering, Technical, Community  
///   AttackTypes: Spoofing, UnauthorizedJoin, VoteManipulation, InformationLeak  
///   DefenseTypes: AccessControl, MemberValidation, QuorumRequirement, AuditLogging

enum WorkingGroupType           { Editorial, Steering, Technical, Community }
enum WorkingGroupAttackType     { Spoofing, UnauthorizedJoin, VoteManipulation, InformationLeak }
enum WorkingGroupDefenseType    { AccessControl, MemberValidation, QuorumRequirement, AuditLogging }

error WG__NotAuthorized();
error WG__InvalidSignature();
error WG__TooManyRequests();
error WG__QuorumNotMet();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE WORKING GROUP
//    • ❌ no checks: anyone may join or vote → UnauthorizedJoin, VoteManipulation
////////////////////////////////////////////////////////////////////////////////
contract WorkingGroupVuln {
    mapping(uint256 => address[]) public members;
    mapping(uint256 => uint256)    public votes;
    event Joined(
        address indexed who,
        uint256           groupId,
        WorkingGroupType  gtype,
        WorkingGroupAttackType attack
    );
    event Voted(
        address indexed who,
        uint256           groupId,
        WorkingGroupType  gtype,
        WorkingGroupAttackType attack
    );

    function join(uint256 groupId, WorkingGroupType gtype) external {
        members[groupId].push(msg.sender);
        emit Joined(msg.sender, groupId, gtype, WorkingGroupAttackType.UnauthorizedJoin);
    }

    function vote(uint256 groupId, WorkingGroupType gtype) external {
        // no membership check
        votes[groupId]++;
        emit Voted(msg.sender, groupId, gtype, WorkingGroupAttackType.VoteManipulation);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates spoofing and vote stuffing
////////////////////////////////////////////////////////////////////////////////
contract Attack_WorkingGroup {
    WorkingGroupVuln public target;

    constructor(WorkingGroupVuln _t) { target = _t; }

    function spoofJoin(uint256 groupId) external {
        target.join(groupId, WorkingGroupType.Community);
    }

    function stuffVotes(uint256 groupId, uint256 count) external {
        for (uint i = 0; i < count; i++) {
            target.vote(groupId, WorkingGroupType.Community);
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may add members
////////////////////////////////////////////////////////////////////////////////
contract WorkingGroupSafeAccess {
    mapping(uint256 => address[]) public members;
    address public owner;
    event Joined(
        address indexed who,
        uint256           groupId,
        WorkingGroupType  gtype,
        WorkingGroupDefenseType defense
    );

    error WG__NotAuthorized();

    constructor() { owner = msg.sender; }

    function addMember(uint256 groupId, address member, WorkingGroupType gtype) external {
        if (msg.sender != owner) revert WG__NotAuthorized();
        members[groupId].push(member);
        emit Joined(member, groupId, gtype, WorkingGroupDefenseType.AccessControl);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH MEMBER VALIDATION & RATE LIMIT
//    • ✅ Defense: MemberValidation – only registered may vote  
//               RateLimit – cap votes per block
////////////////////////////////////////////////////////////////////////////////
contract WorkingGroupSafeValidation {
    mapping(address => bool)     public isMember;
    mapping(uint256 => uint256)  public votes;
    mapping(address => uint256)  public lastBlock;
    mapping(address => uint256)  public votesInBlock;
    uint256 public constant MAX_VOTES = 3;

    event Voted(
        address indexed who,
        uint256           groupId,
        WorkingGroupType  gtype,
        WorkingGroupDefenseType defense
    );

    error WG__NotAuthorized();
    error WG__TooManyRequests();

    function register(address member) external {
        // open registration stub
        isMember[member] = true;
    }

    function vote(uint256 groupId, WorkingGroupType gtype) external {
        if (!isMember[msg.sender]) revert WG__NotAuthorized();
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]   = block.number;
            votesInBlock[msg.sender] = 0;
        }
        votesInBlock[msg.sender]++;
        if (votesInBlock[msg.sender] > MAX_VOTES) revert WG__TooManyRequests();

        votes[groupId]++;
        emit Voted(msg.sender, groupId, gtype, WorkingGroupDefenseType.MemberValidation);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH QUORUM REQUIREMENT & AUDIT LOGGING
//    • ✅ Defense: QuorumRequirement – require min votes to pass  
//               AuditLogging – record every action
////////////////////////////////////////////////////////////////////////////////
contract WorkingGroupSafeAdvanced {
    mapping(uint256 => address[]) public members;
    mapping(uint256 => uint256)    public votes;
    mapping(address => uint256)    public lastBlock;
    mapping(address => uint256)    public actionsInBlock;
    mapping(uint256 => bool)       public passed;
    uint256 public quorum;
    uint256 public constant MAX_ACTIONS = 5;

    event Joined(
        address indexed who,
        uint256           groupId,
        WorkingGroupType  gtype,
        WorkingGroupDefenseType defense
    );
    event Voted(
        address indexed who,
        uint256           groupId,
        WorkingGroupType  gtype,
        WorkingGroupDefenseType defense
    );
    event DecisionMade(
        uint256           groupId,
        bool              passed,
        WorkingGroupDefenseType defense
    );

    error WG__NotAuthorized();
    error WG__TooManyRequests();
    error WG__QuorumNotMet();

    constructor(uint256 _quorum) {
        quorum = _quorum;
    }

    function registerMember(uint256 groupId, address member, WorkingGroupType gtype) external {
        // open admin stub
        members[groupId].push(member);
        emit Joined(member, groupId, gtype, WorkingGroupDefenseType.AuditLogging);
    }

    function vote(uint256 groupId, WorkingGroupType gtype) external {
        // rate-limit per member
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]   = block.number;
            actionsInBlock[msg.sender] = 0;
        }
        actionsInBlock[msg.sender]++;
        if (actionsInBlock[msg.sender] > MAX_ACTIONS) revert WG__TooManyRequests();

        votes[groupId]++;
        emit Voted(msg.sender, groupId, gtype, WorkingGroupDefenseType.QuorumRequirement);
    }

    function finalize(uint256 groupId) external {
        if (votes[groupId] < quorum) revert WG__QuorumNotMet();
        passed[groupId] = true;
        emit DecisionMade(groupId, true, WorkingGroupDefenseType.QuorumRequirement);
    }
}
