// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title ThreatAssessmentSuite.sol
/// @notice On‑chain analogues of “Threat Assessment” patterns:
///   Types: Qualitative, Quantitative, Hybrid  
///   AttackTypes: FalseData, ReplayAssessment, FloodAssessment  
///   DefenseTypes: Validation, ImmutableRecord, RateLimit  

error TA__NotOwner();
error TA__AlreadySet();
error TA__TooMany();

///─────────────────────────────────────────────────────────────────────────────
/// Type definitions
///─────────────────────────────────────────────────────────────────────────────
enum ThreatAssessmentType        { Qualitative, Quantitative, Hybrid }
enum ThreatAssessmentAttackType  { FalseData, ReplayAssessment, FloodAssessment }
enum ThreatAssessmentDefenseType { Validation, ImmutableRecord, RateLimit }

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE ASSESSMENT STORE
///    • no access control  
///    • Attack: inject false data or replay  
///─────────────────────────────────────────────────────────────────────────────
contract ThreatAssessmentVuln {
    mapping(uint256 => ThreatAssessmentType) public assessments;
    event AssessmentSet(
        uint256 indexed id,
        ThreatAssessmentType t,
        ThreatAssessmentAttackType attack
    );

    /// anyone may set or overwrite any assessment
    function setAssessment(uint256 id, ThreatAssessmentType t) external {
        assessments[id] = t;
        emit AssessmentSet(id, t, ThreatAssessmentAttackType.FalseData);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB
///    • replay the same id or flood many ids  
///─────────────────────────────────────────────────────────────────────────────
contract Attack_ThreatAssessment {
    ThreatAssessmentVuln public target;
    constructor(ThreatAssessmentVuln _t) { target = _t; }

    /// flood many assessments with the same false type
    function flood(uint256[] calldata ids, ThreatAssessmentType t) external {
        for (uint i = 0; i < ids.length; i++) {
            target.setAssessment(ids[i], t);
        }
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE ASSESSMENT STORE
///    • only owner may set  
///    • one‑time per id  
///    • rate‑limit per block  
///─────────────────────────────────────────────────────────────────────────────
contract ThreatAssessmentSafe {
    mapping(uint256 => ThreatAssessmentType) public assessments;
    mapping(address => uint256)        public lastBlock;
    mapping(address => uint256)        public countInBlock;
    address public owner;
    uint256 public constant MAX_PER_BLOCK = 5;

    event AssessmentLogged(
        uint256 indexed id,
        ThreatAssessmentType t,
        ThreatAssessmentDefenseType defense
    );

    constructor() {
        owner = msg.sender;
    }

    function setAssessment(uint256 id, ThreatAssessmentType t) external {
        if (msg.sender != owner) revert TA__NotOwner();
        if (assessments[id] == ThreatAssessmentType.Qualitative ||
            assessments[id] == ThreatAssessmentType.Quantitative ||
            assessments[id] == ThreatAssessmentType.Hybrid) {
            revert TA__AlreadySet();
        }
        // rate‑limit per block
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_PER_BLOCK) revert TA__TooMany();

        assessments[id] = t;
        emit AssessmentLogged(id, t, ThreatAssessmentDefenseType.Validation);
        emit AssessmentLogged(id, t, ThreatAssessmentDefenseType.ImmutableRecord);
        emit AssessmentLogged(id, t, ThreatAssessmentDefenseType.RateLimit);
    }
}
