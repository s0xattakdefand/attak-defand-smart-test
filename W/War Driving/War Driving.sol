// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WarDrivingSuite.sol
/// @notice On‑chain analogues of “War Driving” patterns:
///   Types: PassiveScan, ActiveProbe, RogueAP, SignalMapping  
///   AttackTypes: SSIDSpoof, ProbeFlood, RogueBroadcast, MapTamper  
///   DefenseTypes: AuthenticatedScan, ProbeRateLimit, APWhitelist, IntegrityCheck  

enum WarDrivingType         { PassiveScan, ActiveProbe, RogueAP, SignalMapping }
enum WarDrivingAttackType   { SSIDSpoof, ProbeFlood, RogueBroadcast, MapTamper }
enum WarDrivingDefenseType  { AuthenticatedScan, ProbeRateLimit, APWhitelist, IntegrityCheck }

error WD__NotOwner();
error WD__TooManyProbes();
error WD__APNotAllowed();
error WD__BadData();

////////////////////////////////////////////////////////////////////////
// 1) PASSIVE SCAN (VULNERABLE)
//    • logs all visible SSIDs with no access control
//    • Attack: SSID spoofing via fake scan entries
////////////////////////////////////////////////////////////////////////
contract WarDrivingVuln1 {
    event NetworkDetected(address indexed scanner, string ssid, uint8 channel, WarDrivingAttackType attack);

    /// ❌ anyone may log any SSID
    function scan(string calldata ssid, uint8 channel) external {
        emit NetworkDetected(msg.sender, ssid, channel, WarDrivingAttackType.SSIDSpoof);
    }
}

contract Attack_WarDriving1 {
    WarDrivingVuln1 public target;
    constructor(WarDrivingVuln1 _t) { target = _t; }

    /// attacker spoofs SSID
    function spoof(string calldata fakeSSID, uint8 ch) external {
        target.scan(fakeSSID, ch);
    }
}

contract WarDrivingSafe1 {
    address public owner;
    event NetworkDetected(address indexed scanner, string ssid, uint8 channel, WarDrivingDefenseType defense);

    constructor() { owner = msg.sender; }

    /// ✅ only owner may record passive scan
    function scan(string calldata ssid, uint8 channel) external {
        if (msg.sender != owner) revert WD__NotOwner();
        emit NetworkDetected(msg.sender, ssid, channel, WarDrivingDefenseType.AuthenticatedScan);
    }
}

////////////////////////////////////////////////////////////////////////
// 2) ACTIVE PROBE (FLOOD)
//    • sends probe requests and logs responses, unlimited
//    • Attack: flood with many probes
//    • Defense: rate‑limit probes per scanner per block
////////////////////////////////////////////////////////////////////////
contract WarDrivingVuln2 {
    event Probe(address indexed scanner, string ssid, WarDrivingAttackType attack);

    function probe(string calldata ssid) external {
        emit Probe(msg.sender, ssid, WarDrivingAttackType.ProbeFlood);
    }
}

contract Attack_WarDriving2 {
    WarDrivingVuln2 public target;
    constructor(WarDrivingVuln2 _t) { target = _t; }

    function flood(string calldata ssid, uint n) external {
        for (uint i; i < n; i++) {
            target.probe(ssid);
        }
    }
}

contract WarDrivingSafe2 {
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public countInBlock;
    uint256 public constant MAX_PROBES_PER_BLOCK = 10;
    event Probe(address indexed scanner, string ssid, WarDrivingDefenseType defense);
    error WD__TooManyProbes();

    function probe(string calldata ssid) external {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_PROBES_PER_BLOCK) revert WD__TooManyProbes();
        emit Probe(msg.sender, ssid, WarDrivingDefenseType.ProbeRateLimit);
    }
}

////////////////////////////////////////////////////////////////////////
// 3) ROGUE AP BROADCAST
//    • anyone may register a fake AP for clients
//    • Attack: broadcast rogue SSID
//    • Defense: whitelist only approved SSIDs
////////////////////////////////////////////////////////////////////////
contract WarDrivingVuln3 {
    event APBroadcast(address indexed reporter, string ssid, WarDrivingAttackType attack);

    function broadcastAP(string calldata ssid) external {
        emit APBroadcast(msg.sender, ssid, WarDrivingAttackType.RogueBroadcast);
    }
}

contract Attack_WarDriving3 {
    WarDrivingVuln3 public target;
    constructor(WarDrivingVuln3 _t) { target = _t; }

    function announce(string calldata fakeSSID) external {
        target.broadcastAP(fakeSSID);
    }
}

contract WarDrivingSafe3 {
    mapping(string => bool) public allowedSSIDs;
    address public owner;
    event APBroadcast(address indexed reporter, string ssid, WarDrivingDefenseType defense);
    error WD__APNotAllowed();

    constructor() { owner = msg.sender; }

    function setAllowed(string calldata ssid, bool ok) external {
        if (msg.sender != owner) revert WD__NotOwner();
        allowedSSIDs[ssid] = ok;
    }

    function broadcastAP(string calldata ssid) external {
        if (!allowedSSIDs[ssid]) revert WD__APNotAllowed();
        emit APBroadcast(msg.sender, ssid, WarDrivingDefenseType.APWhitelist);
    }
}

////////////////////////////////////////////////////////////////////////
// 4) SIGNAL MAPPING
//    • logs signal strength map, no integrity => tampering
//    • Attack: map tamper with false data
//    • Defense: log only hash of data for integrity
////////////////////////////////////////////////////////////////////////
contract WarDrivingVuln4 {
    event MapData(address indexed mapper, int8 rssi, uint8 channel, WarDrivingAttackType attack);

    function logSignal(int8 rssi, uint8 channel) external {
        emit MapData(msg.sender, rssi, channel, WarDrivingAttackType.MapTamper);
    }
}

contract Attack_WarDriving4 {
    WarDrivingVuln4 public target;
    constructor(WarDrivingVuln4 _t) { target = _t; }

    function falsify(int8 fakeRssi, uint8 ch) external {
        target.logSignal(fakeRssi, ch);
    }
}

contract WarDrivingSafe4 {
    event MapHash(address indexed mapper, bytes32 dataHash, WarDrivingDefenseType defense);
    error WD__BadData();

    function logSignal(int8 rssi, uint8 channel) external {
        // simple sanity: RSSI must be in [-100, 0]
        if (rssi < -100 || rssi > 0) revert WD__BadData();
        bytes32 hash = keccak256(abi.encodePacked(msg.sender, rssi, channel));
        emit MapHash(msg.sender, hash, WarDrivingDefenseType.IntegrityCheck);
    }
}
