// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title TrustPortSuite.sol
/// @notice On‑chain analogues of “Trust Ports” patterns:
///   Types: Basic, Bulk, Spoofable, Expirable  
///   AttackTypes: SpoofAdd, FloodAdd, SpoofCheck, ExpiredBypass  
///   DefenseTypes: OwnerAuth, RateLimit, FixedCheck, TTLExpire  

enum TrustPortType         { Basic, Bulk, Spoofable, Expirable }
enum TrustPortAttackType   { SpoofAdd, FloodAdd, SpoofCheck, ExpiredBypass }
enum TrustPortDefenseType  { OwnerAuth, RateLimit, FixedCheck, TTLExpire }

error TP__NotOwner();
error TP__TooMany();
error TP__SpoofDetected();
error TP__TrustExpired();

////////////////////////////////////////////////////////////////////////
// 1) BASIC TRUST ADD (NO ACCESS CONTROL)
//    • Vulnerable: anyone may mark any port trusted
//    • Attack: spoof‑add trust to protected port
//    • Defense: restrict to owner
////////////////////////////////////////////////////////////////////////
contract TrustPortVuln1 {
    mapping(uint16 => bool) public trusted;
    event TrustAdded(uint16 port, TrustPortAttackType attack);

    function addTrust(uint16 port) external {
        // ❌ unrestricted
        trusted[port] = true;
        emit TrustAdded(port, TrustPortAttackType.SpoofAdd);
    }
}

contract Attack_TrustPort1 {
    TrustPortVuln1 public target;
    constructor(TrustPortVuln1 _t) { target = _t; }
    function spoofAdd(uint16 port) external {
        // attacker marks any port trusted
        target.addTrust(port);
    }
}

contract TrustPortSafe1 {
    mapping(uint16 => bool) public trusted;
    address public owner;
    event TrustAdded(uint16 port, TrustPortDefenseType defense);

    constructor() { owner = msg.sender; }

    function addTrust(uint16 port) external {
        if (msg.sender != owner) revert TP__NotOwner();
        trusted[port] = true;
        emit TrustAdded(port, TrustPortDefenseType.OwnerAuth);
    }
}

////////////////////////////////////////////////////////////////////////
// 2) BULK TRUST ADD (DoS)
//    • Vulnerable: unlimited bulk adds
//    • Attack: flood addTrustBulk to exhaust gas/events
//    • Defense: cap bulk size
////////////////////////////////////////////////////////////////////////
contract TrustPortVuln2 {
    mapping(uint16 => bool) public trusted;
    event TrustBulk(uint16 port, TrustPortAttackType attack);

    function addTrustBulk(uint16[] calldata ports) external {
        for (uint i; i < ports.length; i++) {
            trusted[ports[i]] = true;
            emit TrustBulk(ports[i], TrustPortAttackType.FloodAdd);
        }
    }
}

contract Attack_TrustPort2 {
    TrustPortVuln2 public target;
    constructor(TrustPortVuln2 _t) { target = _t; }
    function floodAdd(uint16[] calldata ports) external {
        target.addTrustBulk(ports);
    }
}

contract TrustPortSafe2 {
    mapping(uint16 => bool) public trusted;
    uint256 public constant MAX_BULK = 50;
    error TP__TooMany();
    event TrustBulk(uint16 port, TrustPortDefenseType defense);

    function addTrustBulk(uint16[] calldata ports) external {
        if (ports.length > MAX_BULK) revert TP__TooMany();
        for (uint i; i < ports.length; i++) {
            trusted[ports[i]] = true;
            emit TrustBulk(ports[i], TrustPortDefenseType.RateLimit);
        }
    }
}

////////////////////////////////////////////////////////////////////////
// 3) SPOOFABLE TRUST CHECK
//    • Vulnerable: checkTrust accepts user‑supplied “who” param
//    • Attack: spoof check by supplying victim address
//    • Defense: use msg.sender only
////////////////////////////////////////////////////////////////////////
contract TrustPortVuln3 {
    mapping(address => mapping(uint16 => bool)) public trusted;
    event Checked(uint16 port, address who, TrustPortAttackType attack);

    function addTrust(uint16 port) external {
        trusted[msg.sender][port] = true;
    }
    function checkTrust(uint16 port, address who) external view returns (bool) {
        emit Checked(port, who, TrustPortAttackType.SpoofCheck);
        return trusted[who][port];
    }
}

contract Attack_TrustPort3 {
    TrustPortVuln3 public target;
    constructor(TrustPortVuln3 _t) { target = _t; }
    function spoofCheck(uint16 port, address victim) external view returns (bool) {
        // attacker queries victim’s trust status
        return target.checkTrust(port, victim);
    }
}

contract TrustPortSafe3 {
    mapping(address => mapping(uint16 => bool)) public trusted;
    event Checked(uint16 port, TrustPortDefenseType defense);

    function addTrust(uint16 port) external {
        trusted[msg.sender][port] = true;
    }
    function checkTrust(uint16 port) external view returns (bool) {
        emit Checked(port, TrustPortDefenseType.FixedCheck);
        return trusted[msg.sender][port];
    }
}

////////////////////////////////////////////////////////////////////////
// 4) EXPIRABLE TRUST ENTRIES
//    • Vulnerable: trust never expires
//    • Attack: bypass trust long after it should expire
//    • Defense: enforce TTL
////////////////////////////////////////////////////////////////////////
contract TrustPortVuln4 {
    mapping(uint16 => uint256) public expiry;
    event Used(uint16 port, TrustPortAttackType attack);

    function addTrust(uint16 port, uint256 ttl) external {
        expiry[port] = block.timestamp + ttl;
    }
    function usePort(uint16 port) external view returns (bool) {
        emit Used(port, TrustPortAttackType.ExpiredBypass);
        return expiry[port] != 0;
    }
}

contract Attack_TrustPort4 {
    TrustPortVuln4 public target;
    constructor(TrustPortVuln4 _t) { target = _t; }
    function bypass(uint16 port) external view returns (bool) {
        // even after ttl, usePort returns true
        return target.usePort(port);
    }
}

contract TrustPortSafe4 {
    mapping(uint16 => uint256) public expiry;
    error TP__TrustExpired();
    event Used(uint16 port, TrustPortDefenseType defense);

    function addTrust(uint16 port, uint256 ttl) external {
        expiry[port] = block.timestamp + ttl;
    }
    function usePort(uint16 port) external view returns (bool) {
        if (block.timestamp > expiry[port]) revert TP__TrustExpired();
        emit Used(port, TrustPortDefenseType.TTLExpire);
        return true;
    }
}
