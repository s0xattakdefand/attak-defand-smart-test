// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title ZeroDayAttackSuite.sol
/// @notice On-chain analogues of “Zero Day Attack” exploitation patterns:
///   Types: Remote, Local, ClientSide, SupplyChain  
///   AttackTypes: Exploit, Ransomware, Worm, Trojan  
///   DefenseTypes: Patching, IDS, Honeypot, ThreatIntel  

enum ZeroDayAttackType        { Remote, Local, ClientSide, SupplyChain }
enum ZeroDayAttackAttackType  { Exploit, Ransomware, Worm, Trojan }
enum ZeroDayAttackDefenseType { Patching, IDS, Honeypot, ThreatIntel }

error ZDA__NotPatched();
error ZDA__Detected();
error ZDA__TooFrequent();
error ZDA__Unauthorized();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE EXECUTOR
//    • ❌ no checks: any exploit succeeds and is logged
////////////////////////////////////////////////////////////////////////////////
contract ZeroDayAttackVuln {
    event AttackExecuted(
        address               indexed who,
        ZeroDayAttackType     atype,
        bytes                 payload,
        ZeroDayAttackAttackType attack
    );

    function executeAttack(ZeroDayAttackType atype, bytes calldata payload) external {
        // no validation or defense
        emit AttackExecuted(msg.sender, atype, payload, ZeroDayAttackAttackType.Exploit);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates ransomware drop and worm spread
////////////////////////////////////////////////////////////////////////////////
contract Attack_ZeroDayAttack {
    ZeroDayAttackVuln public target;
    constructor(ZeroDayAttackVuln _t) { target = _t; }

    function dropRansomware(bytes calldata payload) external {
        target.executeAttack(ZeroDayAttackType.Remote, payload);
    }

    function spreadWorm(bytes calldata payload, uint256 times) external {
        for (uint i = 0; i < times; i++) {
            target.executeAttack(ZeroDayAttackType.ClientSide, payload);
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH PATCHING
//    • ✅ Defense: Patching – must be on a patched version
////////////////////////////////////////////////////////////////////////////////
contract ZeroDayAttackSafePatching {
    mapping(bytes32 => bool) public patchedVersions;
    event AttackBlocked(
        address               indexed who,
        ZeroDayAttackType     atype,
        bytes                 payload,
        ZeroDayAttackDefenseType defense
    );
    event AttackExecuted(
        address               indexed who,
        ZeroDayAttackType     atype,
        bytes                 payload,
        ZeroDayAttackAttackType attack
    );

    /// owner marks versions as patched
    address public owner;
    constructor() { owner = msg.sender; }

    function setPatchedVersion(bytes32 version, bool ok) external {
        require(msg.sender == owner, "only owner");
        patchedVersions[version] = ok;
    }

    function executeAttack(bytes32 version, ZeroDayAttackType atype, bytes calldata payload) external {
        if (!patchedVersions[version]) {
            // exploit succeeds
            emit AttackExecuted(msg.sender, atype, payload, ZeroDayAttackAttackType.Exploit);
        } else {
            // blocked by patch
            emit AttackBlocked(msg.sender, atype, payload, ZeroDayAttackDefenseType.Patching);
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH IDS
//    • ✅ Defense: IDS – detect and revert exploit attempts
////////////////////////////////////////////////////////////////////////////////
contract ZeroDayAttackSafeIDS {
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public attempts;
    uint256 public constant MAX_ATTEMPTS = 3;

    event IntrusionDetected(
        address               indexed who,
        ZeroDayAttackType     atype,
        string                reason,
        ZeroDayAttackDefenseType defense
    );
    event AttackExecuted(
        address               indexed who,
        ZeroDayAttackType     atype,
        bytes                 payload,
        ZeroDayAttackAttackType attack
    );

    function executeAttack(ZeroDayAttackType atype, bytes calldata payload) external {
        // simple rate-based anomaly detection
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            attempts[msg.sender]  = 0;
        }
        attempts[msg.sender]++;
        if (attempts[msg.sender] > MAX_ATTEMPTS) {
            emit IntrusionDetected(msg.sender, atype, "excessive exploits", ZeroDayAttackDefenseType.IDS);
            revert ZDA__Detected();
        }
        // if under threshold, allow (vulnerable)
        emit AttackExecuted(msg.sender, atype, payload, ZeroDayAttackAttackType.Exploit);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH HONEYPOT & THREAT INTEL
//    • ✅ Defense: Honeypot – divert and monitor attacks  
//               ThreatIntel – block known malicious senders
////////////////////////////////////////////////////////////////////////////////
contract ZeroDayAttackSafeAdvanced {
    mapping(address => bool) public blocked;
    mapping(address => bool) public honeypotActive;
    event DivertedToHoneypot(
        address               indexed who,
        ZeroDayAttackType     atype,
        bytes                 payload,
        ZeroDayAttackDefenseType defense
    );
    event AttackBlocked(
        address               indexed who,
        ZeroDayAttackType     atype,
        string                reason,
        ZeroDayAttackDefenseType defense
    );
    event AttackExecuted(
        address               indexed who,
        ZeroDayAttackType     atype,
        bytes                 payload,
        ZeroDayAttackAttackType attack
    );

    address public owner;
    constructor() { owner = msg.sender; }

    function setBlocked(address who, bool ok) external {
        require(msg.sender == owner, "only owner");
        blocked[who] = ok;
    }
    function setHoneypot(address who, bool ok) external {
        require(msg.sender == owner, "only owner");
        honeypotActive[who] = ok;
    }

    function executeAttack(ZeroDayAttackType atype, bytes calldata payload) external {
        if (blocked[msg.sender]) {
            emit AttackBlocked(msg.sender, atype, "threat intel block", ZeroDayAttackDefenseType.ThreatIntel);
            revert ZDA__Unauthorized();
        }
        if (honeypotActive[msg.sender]) {
            // divert attacker to honeypot
            emit DivertedToHoneypot(msg.sender, atype, payload, ZeroDayAttackDefenseType.Honeypot);
        } else {
            // normal execution (vulnerable behavior)
            emit AttackExecuted(msg.sender, atype, payload, ZeroDayAttackAttackType.Exploit);
        }
    }
}
