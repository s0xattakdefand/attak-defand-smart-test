// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title ThreatSuite.sol
/// @notice On‑chain analogues of common “Threat” handling patterns:
///   Types: External, Internal, Insider, SupplyChain  
///   AttackTypes: Phishing, Malware, Exploit, DDoS  
///   DefenseTypes: PatchManagement, Monitoring, AccessControl, Segmentation  

enum ThreatType         { External, Internal, Insider, SupplyChain }
enum ThreatAttackType   { Phishing, Malware, Exploit, DDoS }
enum ThreatDefenseType  { PatchManagement, Monitoring, AccessControl, Segmentation }

error THR__NotAllowed();
error THR__AlreadyReported();

/// @notice 1) VULNERABLE REPORTER: no access control, generic logging
contract ThreatReporterVuln {
    mapping(uint256 => ThreatType) public threats;
    event ThreatReported(
        uint256 indexed id,
        ThreatType    t,
        ThreatAttackType attack
    );

    /// ❌ anyone can report any threat, and only a generic attack is logged
    function reportThreat(uint256 id, ThreatType t) external {
        threats[id] = t;
        emit ThreatReported(id, t, ThreatAttackType.Phishing);
    }
}

/// @notice 2) ATTACK STUB: spoof internal threats
contract Attack_Threat {
    ThreatReporterVuln public target;
    constructor(ThreatReporterVuln _t) { target = _t; }

    /// attacker reports a false insider threat
    function spoofInsider(uint256 id) external {
        target.reportThreat(id, ThreatType.Insider);
    }
}

/// @notice 3) SAFE REPORTER: owner‑only, one‑time reporting, defense logging
contract ThreatReporterSafe {
    mapping(uint256 => ThreatType) public threats;
    address public owner;
    event ThreatLogged(
        uint256 indexed id,
        ThreatType    t,
        ThreatDefenseType defense
    );

    constructor() {
        owner = msg.sender;
    }

    /// ✅ only owner may report, and only once per id
    function reportThreat(uint256 id, ThreatType t) external {
        if (msg.sender != owner) revert THR__NotAllowed();
        if (threats[id] != ThreatType.External || threats[id] != ThreatType.Internal
         || threats[id] != ThreatType.Insider || threats[id] != ThreatType.SupplyChain) {
            // id already reported
            revert THR__AlreadyReported();
        }
        threats[id] = t;
        emit ThreatLogged(id, t, _selectDefense(t));
    }

    function _selectDefense(ThreatType t) internal pure returns (ThreatDefenseType) {
        if (t == ThreatType.External)    return ThreatDefenseType.PatchManagement;
        if (t == ThreatType.Internal)    return ThreatDefenseType.Monitoring;
        if (t == ThreatType.Insider)     return ThreatDefenseType.AccessControl;
        return ThreatDefenseType.Segmentation;
    }
}
