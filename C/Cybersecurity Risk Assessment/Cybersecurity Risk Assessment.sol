// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title CyberSecurityRiskAssessmentSuite.sol
/// @notice On‑chain analogues of “Cyber Security Risk Assessment” patterns:
///   Types: AssetIdentification, VulnerabilityAnalysis, ThreatAnalysis, RiskEvaluation, RiskTreatment, Monitoring  
///   AttackTypes: SpoofAsset, TamperVulnData, InflateThreat, FakeRiskEval, OmitMonitoring  
///   DefenseTypes: AssetValidation, DataIntegrity, ImmutableRecord, RateLimit, AutomatedMonitor  

enum CyberSecurityRiskAssessmentType      { AssetIdentification, VulnerabilityAnalysis, ThreatAnalysis, RiskEvaluation, RiskTreatment, Monitoring }
enum CyberSecurityRiskAssessmentAttackType{ SpoofAsset, TamperVulnData, InflateThreat, FakeRiskEval, OmitMonitoring }
enum CyberSecurityRiskAssessmentDefenseType{ AssetValidation, DataIntegrity, ImmutableRecord, RateLimit, AutomatedMonitor }

error CSRA__NotOwner();
error CSRA__AlreadySet();
error CSRA__TooMany();
error CSRA__InvalidStage();

////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE ASSESSMENT REGISTRY
//    • no access control, mutable, no rate‑limit
//    • Attack: inject false or tampered assessment data
////////////////////////////////////////////////////////////////////////
contract CyberSecurityRiskAssessmentVuln {
    mapping(uint256 => CyberSecurityRiskAssessmentType) public assessments;
    event AssessmentSet(
        uint256 indexed id,
        CyberSecurityRiskAssessmentType t,
        CyberSecurityRiskAssessmentAttackType attack
    );

    /// anyone may set or overwrite any assessment
    function setAssessment(uint256 id, CyberSecurityRiskAssessmentType t) external {
        assessments[id] = t;
        emit AssessmentSet(id, t, CyberSecurityRiskAssessmentAttackType.TamperVulnData);
    }
}

////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • attacker floods or replays fake assessments
////////////////////////////////////////////////////////////////////////
contract Attack_CyberSecurityRiskAssessment {
    CyberSecurityRiskAssessmentVuln public target;
    constructor(CyberSecurityRiskAssessmentVuln _t) { target = _t; }

    /// flood many fake assessments
    function flood(uint256[] calldata ids, CyberSecurityRiskAssessmentType t) external {
        for (uint i = 0; i < ids.length; i++) {
            target.setAssessment(ids[i], t);
        }
    }

    /// spoof a specific assessment
    function spoof(uint256 id) external {
        target.setAssessment(id, CyberSecurityRiskAssessmentType.RiskTreatment);
    }
}

////////////////////////////////////////////////////////////////////////
// 3) SAFE ASSESSMENT STORE
//    • Defense: only owner may set, one‑time per id, choose defense by type
////////////////////////////////////////////////////////////////////////
contract CyberSecurityRiskAssessmentSafe {
    mapping(uint256 => CyberSecurityRiskAssessmentType) public assessments;
    mapping(uint256 => bool)       private _set;
    address public owner;
    event AssessmentLogged(
        uint256 indexed id,
        CyberSecurityRiskAssessmentType t,
        CyberSecurityRiskAssessmentDefenseType defense
    );

    constructor() {
        owner = msg.sender;
    }

    function setAssessment(uint256 id, CyberSecurityRiskAssessmentType t) external {
        if (msg.sender != owner) revert CSRA__NotOwner();
        if (_set[id]) revert CSRA__AlreadySet();
        _set[id] = true;
        assessments[id] = t;
        emit AssessmentLogged(id, t, _defenseForType(t));
    }

    function _defenseForType(CyberSecurityRiskAssessmentType t) internal pure returns (CyberSecurityRiskAssessmentDefenseType) {
        if (t == CyberSecurityRiskAssessmentType.AssetIdentification)    return CyberSecurityRiskAssessmentDefenseType.AssetValidation;
        if (t == CyberSecurityRiskAssessmentType.VulnerabilityAnalysis)  return CyberSecurityRiskAssessmentDefenseType.DataIntegrity;
        if (t == CyberSecurityRiskAssessmentType.ThreatAnalysis)         return CyberSecurityRiskAssessmentDefenseType.DataIntegrity;
        if (t == CyberSecurityRiskAssessmentType.RiskEvaluation)         return CyberSecurityRiskAssessmentDefenseType.ImmutableRecord;
        if (t == CyberSecurityRiskAssessmentType.RiskTreatment)          return CyberSecurityRiskAssessmentDefenseType.ImmutableRecord;
        return CyberSecurityRiskAssessmentDefenseType.AutomatedMonitor;  // Monitoring
    }
}

////////////////////////////////////////////////////////////////////////
// 4) ADVANCED SAFE WITH RATE‑LIMITING
//    • Defense: cap sets per block, immutable per id
////////////////////////////////////////////////////////////////////////
contract CyberSecurityRiskAssessmentSafeAdvanced {
    mapping(uint256 => CyberSecurityRiskAssessmentType) public assessments;
    mapping(uint256 => bool)       private _set;
    mapping(address => uint256)    public lastBlock;
    mapping(address => uint256)    public countInBlock;
    address public owner;
    uint256 public constant MAX_PER_BLOCK = 5;

    event AssessmentLogged(
        uint256 indexed id,
        CyberSecurityRiskAssessmentType t,
        CyberSecurityRiskAssessmentDefenseType defense
    );
    error CSRA__TooMany();

    constructor() {
        owner = msg.sender;
    }

    function setAssessment(uint256 id, CyberSecurityRiskAssessmentType t) external {
        if (msg.sender != owner) revert CSRA__NotOwner();
        if (_set[id]) revert CSRA__AlreadySet();

        // rate‑limit per block
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_PER_BLOCK) revert CSRA__TooMany();

        _set[id] = true;
        assessments[id] = t;
        emit AssessmentLogged(id, t, CyberSecurityRiskAssessmentDefenseType.RateLimit);
    }
}
