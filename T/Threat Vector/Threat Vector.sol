// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title ThreatVectorSuite.sol
/// @notice On-chain analogues of “Threat Vector” handling patterns:
///   Types: SocialEngineering, PhishingEmail, MalwareDelivery, DDoS
///   AttackTypes: SpearPhishing, LinkInjection, PayloadDrop, TrafficFlood
///   DefenseTypes: UserTraining, EmailFiltering, EndpointProtection, RateLimiting

error TV__NotOwner();
error TV__AlreadyAdded();
error TV__InvalidVector();

///─────────────────────────────────────────────────────────────────────────────
/// Type definitions
///─────────────────────────────────────────────────────────────────────────────
enum ThreatVectorType      { SocialEngineering, PhishingEmail, MalwareDelivery, DDoS }
enum ThreatVectorAttackType{ SpearPhishing, LinkInjection, PayloadDrop, TrafficFlood }
enum ThreatVectorDefenseType{ UserTraining, EmailFiltering, EndpointProtection, RateLimiting }

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE REGISTRY
///    • no access control or validation
///    • Attack: record any vector id/type
///─────────────────────────────────────────────────────────────────────────────
contract ThreatVectorVuln {
    mapping(uint256 => ThreatVectorType) public vectors;
    event VectorRegistered(uint256 indexed id, ThreatVectorType vType, ThreatVectorAttackType attack);

    /// anyone may register or overwrite any vector
    function registerVector(uint256 id, ThreatVectorType vType) external {
        vectors[id] = vType;
        emit VectorRegistered(id, vType, ThreatVectorAttackType.SpearPhishing);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB
///    • uses vulnerable registry to spoof or overwrite vectors
///─────────────────────────────────────────────────────────────────────────────
contract Attack_ThreatVector {
    ThreatVectorVuln public target;
    constructor(ThreatVectorVuln _t) { target = _t; }

    /// attacker registers a malicious payload drop vector
    function injectPayload(uint256 id) external {
        target.registerVector(id, ThreatVectorType.MalwareDelivery);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE REGISTRY
///    • only owner may add
///    • one-time per id
///    • require valid id
///─────────────────────────────────────────────────────────────────────────────
contract ThreatVectorSafe {
    mapping(uint256 => ThreatVectorType) public vectors;
    address public owner;
    event VectorSecured(uint256 indexed id, ThreatVectorType vType, ThreatVectorDefenseType defense);

    constructor() {
        owner = msg.sender;
    }

    function registerVector(uint256 id, ThreatVectorType vType) external {
        if (msg.sender != owner) revert TV__NotOwner();
        if (id == 0) revert TV__InvalidVector();
        // one-time check
        if (vectors[id] == ThreatVectorType.SocialEngineering ||
            vectors[id] == ThreatVectorType.PhishingEmail ||
            vectors[id] == ThreatVectorType.MalwareDelivery ||
            vectors[id] == ThreatVectorType.DDoS) {
            revert TV__AlreadyAdded();
        }
        vectors[id] = vType;
        emit VectorSecured(id, vType, _selectDefense(vType));
    }

    function _selectDefense(ThreatVectorType vType) internal pure returns (ThreatVectorDefenseType) {
        if (vType == ThreatVectorType.SocialEngineering)     return ThreatVectorDefenseType.UserTraining;
        if (vType == ThreatVectorType.PhishingEmail)         return ThreatVectorDefenseType.EmailFiltering;
        if (vType == ThreatVectorType.MalwareDelivery)       return ThreatVectorDefenseType.EndpointProtection;
        return ThreatVectorDefenseType.RateLimiting;
    }
}
