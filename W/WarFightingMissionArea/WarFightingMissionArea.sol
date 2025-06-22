// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WarFightingMissionAreaSuite.sol
/// @notice On‐chain analogues of “War Fighting Mission Area” patterns:
///   Types: Land, Sea, Air, Cyber  
///   AttackTypes: Sabotage, ElectronicWarfare, CyberAttack, SupplyChainAttack  
///   DefenseTypes: AccessControl, Redundancy, ThreatDetection, HardenedComm

enum WFMAType                { Land, Sea, Air, Cyber }
enum WFMAAttackType          { Sabotage, ElectronicWarfare, CyberAttack, SupplyChainAttack }
enum WFMADefenseType         { AccessControl, Redundancy, ThreatDetection, HardenedComm }

error WFMA__NotAuthorized();
error WFMA__TooFrequent();
error WFMA__InvalidSignature();
error WFMA__AnomalyDetected();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE COMMANDER
//
//    • ❌ no controls: anyone may assign mission → Sabotage
////////////////////////////////////////////////////////////////////////////////
contract WFMAVuln {
    mapping(uint256 => WFMAType) public missionArea;
    event MissionAssigned(
        address indexed by,
        uint256           missionId,
        WFMAType          area,
        WFMAAttackType    attack
    );

    function assignMission(uint256 missionId, WFMAType area) external {
        missionArea[missionId] = area;
        emit MissionAssigned(msg.sender, missionId, area, WFMAAttackType.Sabotage);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//    • simulates electronic warfare & supply chain attack
////////////////////////////////////////////////////////////////////////////////
contract Attack_WFMA {
    WFMAVuln public target;

    constructor(WFMAVuln _t) {
        target = _t;
    }

    function jamMission(uint256 missionId) external {
        // override area to disrupt ops
        target.assignMission(missionId, WFMAType.Cyber);
    }

    function corruptSupply(uint256 missionId) external {
        target.assignMission(missionId, WFMAType.Sea);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//
//    • ✅ Defense: AccessControl – only commander may assign
////////////////////////////////////////////////////////////////////////////////
contract WFMASafeAccess {
    mapping(address => bool) public commanders;
    mapping(uint256 => WFMAType) public missionArea;
    event MissionAssigned(
        address indexed by,
        uint256           missionId,
        WFMAType          area,
        WFMADefenseType   defense
    );

    error WFMA__NotAuthorized();

    constructor() {
        commanders[msg.sender] = true;
    }

    function setCommander(address who, bool ok) external {
        require(commanders[msg.sender], "admin only");
        commanders[who] = ok;
    }

    function assignMission(uint256 missionId, WFMAType area) external {
        if (!commanders[msg.sender]) revert WFMA__NotAuthorized();
        missionArea[missionId] = area;
        emit MissionAssigned(msg.sender, missionId, area, WFMADefenseType.AccessControl);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH REDUNDANCY & RATE LIMIT
//
//    • ✅ Defense: Redundancy – require dual assignment  
//               RateLimit – cap assignments per block
////////////////////////////////////////////////////////////////////////////////
contract WFMASafeRedundancy {
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public assignsInBlock;
    mapping(uint256 => mapping(address=>bool)) public votes;
    mapping(uint256 => uint256) public voteCount;
    mapping(uint256 => WFMAType)   public missionArea;
    uint256 public constant MAX_IN_BLOCK = 3;

    event MissionAssigned(
        uint256           missionId,
        WFMAType          area,
        WFMADefenseType   defense
    );
    error WFMA__TooFrequent();

    function assignMission(uint256 missionId, WFMAType area) external {
        // rate-limit per assigner
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            assignsInBlock[msg.sender] = 0;
        }
        assignsInBlock[msg.sender]++;
        if (assignsInBlock[msg.sender] > MAX_IN_BLOCK) revert WFMA__TooFrequent();

        // redundancy: each assigner votes once
        if (!votes[missionId][msg.sender]) {
            votes[missionId][msg.sender] = true;
            voteCount[missionId]++;
        }
        // commit when two votes
        if (voteCount[missionId] >= 2) {
            missionArea[missionId] = area;
            emit MissionAssigned(missionId, area, WFMADefenseType.Redundancy);
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH THREAT DETECTION & HARDENED COMM
//
//    • ✅ Defense: ThreatDetection – log anomalies  
//               HardenedComm – require signed order
////////////////////////////////////////////////////////////////////////////////
contract WFMASafeAdvanced {
    address public signer;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS = 5;
    mapping(uint256 => WFMAType) public missionArea;

    event MissionAssigned(
        address indexed by,
        uint256           missionId,
        WFMAType          area,
        WFMADefenseType   defense
    );
    event Anomaly(
        address indexed by,
        string            reason,
        WFMADefenseType   defense
    );

    error WFMA__TooManyRequests();
    error WFMA__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function assignMission(
        uint256 missionId,
        WFMAType area,
        bytes calldata sig
    ) external {
        // rate-limit per sender
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) {
            emit Anomaly(msg.sender, "rate limit exceeded", WFMADefenseType.ThreatDetection);
            revert WFMA__TooManyRequests();
        }

        // verify signed order (missionId||area)
        bytes32 msgHash = keccak256(abi.encodePacked(missionId, area));
        bytes32 ethMsg  = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8,bytes32,bytes32));
        if (ecrecover(ethMsg, v, r, s) != signer) {
            emit Anomaly(msg.sender, "invalid signature", WFMADefenseType.ThreatDetection);
            revert WFMA__InvalidSignature();
        }

        // commit assignment over hardened communication
        missionArea[missionId] = area;
        emit MissionAssigned(msg.sender, missionId, area, WFMADefenseType.HardenedComm);
    }
}
