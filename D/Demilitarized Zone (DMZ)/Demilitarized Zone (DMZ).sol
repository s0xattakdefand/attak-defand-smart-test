// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DemilitarizedZoneSuite.sol
/// @notice On‑chain analogues of “Demilitarized Zone” (DMZ) network patterns:
///   Types: Service, PublicNetwork, Hybrid, IDSZone  
///   AttackTypes: UnauthorizedAccess, FirewallBypass, LateralMovement  
///   DefenseTypes: FirewallRules, BastionHost, IDSMonitoring, RateLimit  

enum DMZType             { Service, PublicNetwork, Hybrid, IDSZone }
enum DMZAttackType       { UnauthorizedAccess, FirewallBypass, LateralMovement }
enum DMZDefenseType      { FirewallRules, BastionHost, IDSMonitoring, RateLimit }

error DMZ__NotAllowed();
error DMZ__Bypass();
error DMZ__TooManyRequests();
error DMZ__BadConfig();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE DMZ (no perimeter controls)
///    • anyone may host or access services → UnauthorizedAccess
///─────────────────────────────────────────────────────────────────────────────
contract DMZVuln {
    mapping(address => bytes) public services;
    event ServiceAccessed(
        address indexed who,
        DMZType    zone,
        bytes      payload,
        DMZAttackType attack
    );

    function hostService(DMZType zone, bytes calldata payload) external {
        services[msg.sender] = payload;
        emit ServiceAccessed(msg.sender, zone, payload, DMZAttackType.UnauthorizedAccess);
    }

    function accessService(address host, DMZType zone) external view {
        // ❌ no access checks
        emit ServiceAccessed(msg.sender, zone, services[host], DMZAttackType.UnauthorizedAccess);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB (bypass & lateral movement)
///─────────────────────────────────────────────────────────────────────────────
contract Attack_DMZ {
    DMZVuln public target;
    constructor(DMZVuln _t) { target = _t; }

    function bypass(DMZType zone, bytes calldata payload) external {
        target.hostService(zone, payload);
    }

    function lateralMove(address host, DMZType zone, bytes calldata payload) external {
        target.accessService(host, zone);
        target.hostService(zone, payload);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE DMZ WITH FIREWALL RULES (perimeter control)
///    • Defense: FirewallRules – only whitelisted callers  
///─────────────────────────────────────────────────────────────────────────────
contract DMZSafeFirewall {
    mapping(address => bool) public allowed;
    address public operator;
    event ServiceAccessed(
        address indexed who,
        DMZType    zone,
        bytes      payload,
        DMZDefenseType defense
    );

    constructor() { operator = msg.sender; }

    function setAllowed(address who, bool ok) external {
        if (msg.sender != operator) revert DMZ__NotAllowed();
        allowed[who] = ok;
    }

    function hostService(DMZType zone, bytes calldata payload) external {
        if (!allowed[msg.sender]) revert DMZ__Bypass();
        emit ServiceAccessed(msg.sender, zone, payload, DMZDefenseType.FirewallRules);
    }

    function accessService(address host, DMZType zone) external view {
        if (!allowed[msg.sender]) revert DMZ__Bypass();
        emit ServiceAccessed(msg.sender, zone, services[host], DMZDefenseType.FirewallRules);
    }

    mapping(address => bytes) private services;
    function registerService(bytes calldata payload) external {
        if (!allowed[msg.sender]) revert DMZ__Bypass();
        services[msg.sender] = payload;
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE DMZ WITH BASTION + IDS & RATE‑LIMIT (defense in depth)
///    • Defense: BastionHost, IDSMonitoring, RateLimit  
///─────────────────────────────────────────────────────────────────────────────
contract DMZSafeAdvanced {
    address public bastion;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public countInBlock;
    uint256 public constant MAX_PER_BLOCK = 5;

    event ServiceAccessed(
        address indexed user,
        DMZType    zone,
        bytes      payload,
        DMZDefenseType defense
    );
    event IDSAlert(
        address indexed user,
        DMZType    zone,
        string     msg,
        DMZDefenseType defense
    );

    constructor(address _bastion) {
        bastion = _bastion;
    }

    modifier onlyBastion() {
        if (msg.sender != bastion) revert DMZ__NotAllowed();
        _;
    }

    function proxyHost(address user, DMZType zone, bytes calldata payload) external onlyBastion {
        // rate‑limit per user per block
        if (block.number != lastBlock[user]) {
            lastBlock[user]    = block.number;
            countInBlock[user] = 0;
        }
        countInBlock[user]++;
        if (countInBlock[user] > MAX_PER_BLOCK) {
            emit IDSAlert(user, zone, "Rate limit exceeded", DMZDefenseType.RateLimit);
            revert DMZ__TooManyRequests();
        }
        emit ServiceAccessed(user, zone, payload, DMZDefenseType.BastionHost);
    }

    function unproxiedAccess(DMZType zone) external {
        emit IDSAlert(msg.sender, zone, "Direct access detected", DMZDefenseType.IDSMonitoring);
        revert DMZ__BadConfig();
    }
}
