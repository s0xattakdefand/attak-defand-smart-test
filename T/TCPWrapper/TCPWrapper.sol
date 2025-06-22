// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title TCPWrapperSuite.sol
/// @notice On‑chain analogues of “TCP Wrapper” patterns:
///   Types: HostsAllow, HostsDeny, PortBased, TimeBased  
///   AttackTypes: SpoofAllow, FloodAllow, LogInjection, ExpiredEntry  
///   DefenseTypes: MsgSenderAuth, LimitBulk, HashLogging, TTLExpire  

enum TCPWrapperType        { HostsAllow, HostsDeny, PortBased, TimeBased }
enum TCPWrapperAttackType  { SpoofAllow, FloodAllow, LogInjection, ExpiredEntry }
enum TCPWrapperDefenseType { MsgSenderAuth, LimitBulk, HashLogging, TTLExpire }

error TW__NotOwner();
error TW__TooMany();
error TW__EntryExpired();

////////////////////////////////////////////////////////////////////////
// 1) UNRESTRICTED ACCESS (NO DEFAULT DENY)
//    • Vulnerable: trusts user‑supplied IP param → default allow
//    • Attack: SpoofAllow by passing victim’s IP
//    • Defense: MsgSenderAuth—use msg.sender for identity
////////////////////////////////////////////////////////////////////////
contract TCPWrapperVuln {
    mapping(address => bool) public allowed;
    event Connected(address ip, uint16 port, TCPWrapperAttackType attack);

    function allow(address ip) external {
        // ❌ anyone may allow any IP
        allowed[ip] = true;
    }

    function connect(address ip, uint16 port) external {
        require(allowed[ip], "not allowed");
        emit Connected(ip, port, TCPWrapperAttackType.SpoofAllow);
    }
}

contract Attack_SpoofAllow {
    TCPWrapperVuln public target;
    constructor(TCPWrapperVuln _t) { target = _t; }

    function exploit(address victimIp, uint16 port) external {
        // attacker spoofs victimIp to bypass allow
        target.connect(victimIp, port);
    }
}

contract TCPWrapperSafeAuth {
    mapping(address => bool) public allowed;
    address public owner;
    event Connected(address ip, uint16 port, TCPWrapperDefenseType defense);

    constructor() { owner = msg.sender; }

    function allow(address ip) external {
        if (msg.sender != owner) revert TW__NotOwner();
        allowed[ip] = true;
    }

    function connect(uint16 port) external {
        // ✅ only actual sender may connect
        require(allowed[msg.sender], "not allowed");
        emit Connected(msg.sender, port, TCPWrapperDefenseType.MsgSenderAuth);
    }
}

////////////////////////////////////////////////////////////////////////
// 2) BULK ALLOW FLOOD (DoS)
//    • Vulnerable: no limit on bulk allow → FloodAllow attack
//    • Defense: LimitBulk—cap number per call
////////////////////////////////////////////////////////////////////////
contract TCPWrapperVulnBulk {
    mapping(address => bool) public allowed;
    event BulkAllowed(address ip, TCPWrapperAttackType attack);

    function allowBulk(address[] calldata ips) external {
        for (uint i = 0; i < ips.length; i++) {
            allowed[ips[i]] = true;
            emit BulkAllowed(ips[i], TCPWrapperAttackType.FloodAllow);
        }
    }
}

contract Attack_FloodAllow {
    TCPWrapperVulnBulk public target;
    constructor(TCPWrapperVulnBulk _t) { target = _t; }

    function flood(address[] calldata victims) external {
        target.allowBulk(victims);
    }
}

contract TCPWrapperSafeBulk {
    mapping(address => bool) public allowed;
    uint public constant MAX_BULK = 50;
    event BulkAllowed(address ip, TCPWrapperDefenseType defense);

    function allowBulk(address[] calldata ips) external {
        if (ips.length > MAX_BULK) revert TW__TooMany();
        for (uint i = 0; i < ips.length; i++) {
            allowed[ips[i]] = true;
            emit BulkAllowed(ips[i], TCPWrapperDefenseType.LimitBulk);
        }
    }
}

////////////////////////////////////////////////////////////////////////
// 3) LOG INJECTION
//    • Vulnerable: logs raw IP → attacker can inject misleading entries
//    • Defense: HashLogging—emit only hash of IP
////////////////////////////////////////////////////////////////////////
contract TCPWrapperVulnLog {
    event AllowedLog(address ip, string note);

    function allow(address ip, string calldata note) external {
        // ❌ logs raw IP and note
        emit AllowedLog(ip, note);
    }
}

contract Attack_LogInjection {
    TCPWrapperVulnLog public target;
    constructor(TCPWrapperVulnLog _t) { target = _t; }

    function inject(address ip, string calldata note) external {
        target.allow(ip, note);
    }
}

contract TCPWrapperSafeLog {
    event AllowedLogHash(bytes32 ipHash, TCPWrapperDefenseType defense);

    function allow(address ip) external {
        // ✅ emit only hash to avoid log injection
        emit AllowedLogHash(keccak256(abi.encodePacked(ip)), TCPWrapperDefenseType.HashLogging);
    }
}

////////////////////////////////////////////////////////////////////////
// 4) EXPIRED ENTRY (NO TTL)
//    • Vulnerable: entries never expire → ExpiredEntry attack
//    • Defense: TTLExpire—reject stale entries
////////////////////////////////////////////////////////////////////////
contract TCPWrapperVulnExpiry {
    mapping(address => uint256) public expires;
    event Connected(address ip, uint16 port, TCPWrapperAttackType attack);

    function allow(address ip, uint256 ttl) external {
        // sets a TTL but is ignored by connect
        expires[ip] = block.timestamp + ttl;
    }

    function connect(address ip, uint16 port) external {
        // ❌ does not enforce expiry
        require(expires[ip] != 0, "not allowed");
        emit Connected(ip, port, TCPWrapperAttackType.ExpiredEntry);
    }
}

contract Attack_ExpiredEntry {
    TCPWrapperVulnExpiry public target;
    constructor(TCPWrapperVulnExpiry _t) { target = _t; }

    function exploit(address ip, uint16 port, uint256 ttl) external {
        target.allow(ip, ttl);
        // wait past ttl off‑chain, then connect still succeeds
        target.connect(ip, port);
    }
}

contract TCPWrapperSafeExpiry {
    mapping(address => uint256) public expires;
    event Connected(address ip, uint16 port, TCPWrapperDefenseType defense);

    function allow(address ip, uint256 ttl) external {
        expires[ip] = block.timestamp + ttl;
    }

    function connect(address ip, uint16 port) external {
        if (block.timestamp > expires[ip]) revert TW__EntryExpired();
        emit Connected(ip, port, TCPWrapperDefenseType.TTLExpire);
    }
}
