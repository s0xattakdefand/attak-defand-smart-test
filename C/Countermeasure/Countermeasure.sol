// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title CounterMeasureSuite.sol
/// @notice On‑chain analogues of “Counter Measure” deployment patterns:
///   Types: Firewall, IDS, Antivirus, Patching  
///   AttackTypes: Evasion, Overwhelm, TamperConfig, ExploitStale  
///   DefenseTypes: ConfigValidation, ImmutableConfig, RateLimit, AutoUpdate  

enum CounterMeasureType       { Firewall, IDS, Antivirus, Patching }
enum CounterMeasureAttackType { Evasion, Overwhelm, TamperConfig, ExploitStale }
enum CounterMeasureDefenseType{ ConfigValidation, ImmutableConfig, RateLimit, AutoUpdate }

error CM__NotOwner();
error CM__AlreadySet();
error CM__InvalidType();
error CM__TooMany();
error CM__Expired();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE DEPLOYMENT
//
//    • Vulnerable: anyone may deploy or overwrite any measure
//    • Attack: Overwhelm registry or tamper config
////////////////////////////////////////////////////////////////////////////////
contract CounterMeasureVuln {
    mapping(uint256 => CounterMeasureType) public deployed;
    event MeasureDeployed(uint256 indexed id, CounterMeasureType m, CounterMeasureAttackType attack);

    /// anyone may set or change the counter‑measure at will
    function deploy(uint256 id, CounterMeasureType m) external {
        deployed[id] = m;
        emit MeasureDeployed(id, m, CounterMeasureAttackType.Overwhelm);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//    • Evasion: overwrite to disable desired measure
//    • TamperConfig: change to wrong type
////////////////////////////////////////////////////////////////////////////////
contract Attack_CounterMeasure {
    CounterMeasureVuln public target;
    constructor(CounterMeasureVuln _t) { target = _t; }

    function tamper(uint256 id, CounterMeasureType fake) external {
        target.deploy(id, fake);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE DEPLOYMENT (OWNER‑ONLY, IMMUTABLE)
//    • Defense: ConfigValidation + ImmutableConfig
////////////////////////////////////////////////////////////////////////////////
contract CounterMeasureSafe {
    mapping(uint256 => CounterMeasureType) public deployed;
    address public owner;
    event MeasureDeployed(uint256 indexed id, CounterMeasureType m, CounterMeasureDefenseType defense);

    constructor() {
        owner = msg.sender;
    }

    /// only owner may deploy, and only once per id
    function deploy(uint256 id, CounterMeasureType m) external {
        if (msg.sender != owner)                 revert CM__NotOwner();
        if (deployed[id] == CounterMeasureType.Firewall ||
            deployed[id] == CounterMeasureType.IDS      ||
            deployed[id] == CounterMeasureType.Antivirus ||
            deployed[id] == CounterMeasureType.Patching) revert CM__AlreadySet();
        deployed[id] = m;
        emit MeasureDeployed(id, m, CounterMeasureDefenseType.ImmutableConfig);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) ADVANCED SAFE (RATE‑LIMITED + AUTO‑UPDATE)
//    • Defense: RateLimit per owner per block + TTL‑based expiry & renewal
////////////////////////////////////////////////////////////////////////////////
contract CounterMeasureSafeAdvanced {
    struct CM { CounterMeasureType m; uint256 expiry; }
    mapping(uint256 => CM) public deployed;
    address public owner;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public countInBlock;
    uint256 public constant MAX_PER_BLOCK = 3;
    uint256 public constant TTL = 1 hours;

    event MeasureDeployed(uint256 indexed id, CounterMeasureType m, CounterMeasureDefenseType defense);

    constructor() {
        owner = msg.sender;
    }

    /// rate‑limit deploy calls per block and set TTL expiry
    function deploy(uint256 id, CounterMeasureType m) external {
        if (msg.sender != owner) revert CM__NotOwner();

        // rate‑limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_PER_BLOCK) revert CM__TooMany();

        // apply or renew
        deployed[id] = CM({ m: m, expiry: block.timestamp + TTL });
        emit MeasureDeployed(id, m, CounterMeasureDefenseType.RateLimit);
    }

    /// auto‑update expired measures off‑chain: check isActive before relying
    function isActive(uint256 id) external view returns (bool) {
        return deployed[id].expiry >= block.timestamp;
    }

    /// owner can trigger auto‑renewal of a given measure before expiry
    function renew(uint256 id) external {
        if (msg.sender != owner) revert CM__NotOwner();
        CM storage cm = deployed[id];
        if (cm.expiry < block.timestamp) revert CM__Expired();
        cm.expiry = block.timestamp + TTL;
        emit MeasureDeployed(id, cm.m, CounterMeasureDefenseType.AutoUpdate);
    }
}
