// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WateringHoleAttackSuite.sol
/// @notice On-chain analogues of “Watering Hole Attack” stages:
///   Types: Reconnaissance, Compromise, Delivery, Exfiltration  
///   AttackTypes: Phishing, ExploitKit, DriveByDownload, CredentialHarvest  
///   DefenseTypes: Monitoring, EndpointProtection, NetworkSegmentation, PatchManagement  

enum WHAttackStageType     { Reconnaissance, Compromise, Delivery, Exfiltration }
enum WHAttackAttackType    { Phishing, ExploitKit, DriveByDownload, CredentialHarvest }
enum WHAttackDefenseType   { Monitoring, EndpointProtection, NetworkSegmentation, PatchManagement }

error WHA__NotAuthorized();
error WHA__InvalidSignature();
error WHA__TooManyRequests();
error WHA__NoScan();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE ORCHESTRATOR
//    • ❌ no detection/enforcement: all stages proceed unchecked
////////////////////////////////////////////////////////////////////////////////
contract WHAttackVuln {
    event StageExecuted(
        address indexed who,
        WHAttackStageType     stage,
        bytes                 data,
        WHAttackAttackType    attack
    );

    function executeStage(WHAttackStageType stage, bytes calldata data) external {
        // no defenses
        emit StageExecuted(msg.sender, stage, data, WHAttackAttackType.Phishing);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates each stage of a watering-hole attack
////////////////////////////////////////////////////////////////////////////////
contract Attack_WHAttack {
    WHAttackVuln public target;
    WHAttackStageType public lastStage;
    bytes             public lastData;

    constructor(WHAttackVuln _t) { target = _t; }

    function recon(bytes calldata info) external {
        target.executeStage(WHAttackStageType.Reconnaissance, info);
        lastStage = WHAttackStageType.Reconnaissance;
        lastData = info;
    }

    function compromise(bytes calldata payload) external {
        target.executeStage(WHAttackStageType.Compromise, payload);
        lastStage = WHAttackStageType.Compromise;
        lastData = payload;
    }

    function deliver(bytes calldata exploit) external {
        target.executeStage(WHAttackStageType.Delivery, exploit);
        lastStage = WHAttackStageType.Delivery;
        lastData = exploit;
    }

    function exfiltrate(bytes calldata loot) external {
        target.executeStage(WHAttackStageType.Exfiltration, loot);
        lastStage = WHAttackStageType.Exfiltration;
        lastData = loot;
    }

    function replayLast() external {
        target.executeStage(lastStage, lastData);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH MONITORING
//    • ✅ Defense: Monitoring – require a watcher role to approve execution
////////////////////////////////////////////////////////////////////////////////
contract WHAttackSafeMonitor {
    mapping(address => bool) public watchers;
    event StageExecuted(
        address indexed who,
        WHAttackStageType     stage,
        bytes                 data,
        WHAttackDefenseType   defense
    );

    error WHA__NotAuthorized();

    constructor() {
        watchers[msg.sender] = true;
    }

    function setWatcher(address who, bool ok) external {
        require(watchers[msg.sender], "admin only");
        watchers[who] = ok;
    }

    function executeStage(WHAttackStageType stage, bytes calldata data) external {
        if (!watchers[msg.sender]) revert WHA__NotAuthorized();
        emit StageExecuted(msg.sender, stage, data, WHAttackDefenseType.Monitoring);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH ENDPOINT PROTECTION
//    • ✅ Defense: EndpointProtection – require last scan marker on data
////////////////////////////////////////////////////////////////////////////////
contract WHAttackSafeEndpoint {
    mapping(address => bool) public scanned;
    event StageExecuted(
        address indexed who,
        WHAttackStageType     stage,
        bytes                 data,
        WHAttackDefenseType   defense
    );

    error WHA__NoScan();

    function markScanned(address who) external {
        // stub: designate that this attacker has up-to-date endpoint protections
        scanned[who] = true;
    }

    function executeStage(WHAttackStageType stage, bytes calldata data) external {
        if (!scanned[msg.sender]) revert WHA__NoScan();
        emit StageExecuted(msg.sender, stage, data, WHAttackDefenseType.EndpointProtection);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH NETWORK SEGMENTATION & PATCH MANAGEMENT
//    • ✅ Defense: NetworkSegmentation – only within allowed segment  
//               PatchManagement – ensure payload version is patched
////////////////////////////////////////////////////////////////////////////////
contract WHAttackSafeAdvanced {
    mapping(address => bytes32) public segment;
    mapping(bytes32 => bool)   public allowedSegment;
    mapping(bytes32 => uint256) public patchedVersion;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS = 4;

    event StageExecuted(
        address indexed who,
        WHAttackStageType     stage,
        bytes                 data,
        WHAttackDefenseType   defense
    );
    event Alert(
        address indexed who,
        string                reason,
        WHAttackDefenseType   defense
    );

    error WHA__NotAuthorized();
    error WHA__TooManyRequests();
    error WHA__VersionUnpatched();

    /// admin assigns segment for users
    function setAllowedSegment(bytes32 seg, bool ok) external {
        allowedSegment[seg] = ok;
    }
    function registerSegment(bytes32 seg) external {
        segment[msg.sender] = seg;
    }
    /// admin marks versions as patched
    function setPatchedVersion(uint256 ver, bool ok) external {
        patchedVersion[bytes32(ver)] = ok;
    }

    function executeStage(WHAttackStageType stage, bytes calldata data, uint256 version) external {
        // segmentation check
        if (!allowedSegment[segment[msg.sender]]) revert WHA__NotAuthorized();
        // rate-limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) {
            emit Alert(msg.sender, "rate limit exceeded", WHAttackDefenseType.NetworkSegmentation);
            revert WHA__TooManyRequests();
        }
        // patch check
        if (!patchedVersion[bytes32(version)]) revert WHA__VersionUnpatched();

        emit StageExecuted(msg.sender, stage, data, WHAttackDefenseType.PatchManagement);
    }
}
