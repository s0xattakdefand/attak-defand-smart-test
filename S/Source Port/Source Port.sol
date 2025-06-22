// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title SourcePortSuite.sol
/// @notice Four on‑chain analogues of common “Source Port” patterns:
///   1) Unrestricted Source Port Spoofing  
///   2) Unbounded Port Usage Flood  
///   3) Port‑Based Authentication Bypass  
///   4) Ephemeral Port Expiry  

error SP__NotAllowed();
error SP__TooManyPerPort();
error SP__PortNotAllowed();
error SP__PortExpired();

////////////////////////////////////////////////////////////////////////////////
// 1) UNRESTRICTED SOURCE PORT SPOOFING
//
//    • Type: user supplies srcPort in packet
//    • Attack: sendPacket(spoofedPort,...)
//    • Defense: whitelist ports to trusted values
////////////////////////////////////////////////////////////////////////////////
contract SourcePortVuln1 {
    event Packet(uint16 indexed srcPort, address indexed from, bytes data);

    /// ❌ accepts any srcPort
    function sendPacket(uint16 srcPort, bytes calldata data) external {
        emit Packet(srcPort, msg.sender, data);
    }
}

contract Attack_SourcePort1 {
    SourcePortVuln1 public target;
    constructor(SourcePortVuln1 _t) { target = _t; }

    /// spoof port 12345
    function spoof(bytes calldata data) external {
        target.sendPacket(12345, data);
    }
}

contract SourcePortSafe1 {
    address public owner;
    mapping(uint16 => bool) public allowedPorts;
    event Packet(uint16 indexed srcPort, address indexed from, bytes data);
    event PortAllowed(uint16 port, bool ok);

    constructor() { owner = msg.sender; }

    /// only owner can whitelist ports
    function setAllowedPort(uint16 port, bool ok) external {
        if (msg.sender != owner) revert SP__NotAllowed();
        allowedPorts[port] = ok;
        emit PortAllowed(port, ok);
    }

    /// ✅ enforce whitelist
    function sendPacket(uint16 srcPort, bytes calldata data) external {
        if (!allowedPorts[srcPort]) revert SP__PortNotAllowed();
        emit Packet(srcPort, msg.sender, data);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) UNBOUNDED PORT USAGE FLOOD
//
//    • Type: count uses of each srcPort, no cap → DoS
//    • Attack: flood(port,n)
//    • Defense: rate‑limit per block per port
////////////////////////////////////////////////////////////////////////////////
contract SourcePortVuln2 {
    mapping(uint16 => uint256) public usage;
    event Packet(uint16 indexed srcPort, bytes data);

    function send(uint16 srcPort, bytes calldata data) external {
        usage[srcPort] += 1;
        emit Packet(srcPort, data);
    }
}

contract Attack_SourcePort2 {
    SourcePortVuln2 public target;
    constructor(SourcePortVuln2 _t) { target = _t; }

    function flood(uint16 port, bytes calldata data, uint256 n) external {
        for (uint256 i = 0; i < n; i++) {
            target.send(port, data);
        }
    }
}

contract SourcePortSafe2 {
    mapping(uint16 => uint256) public usage;
    mapping(uint16 => uint256) public lastBlock;
    uint256 public constant MAX_PER_BLOCK = 5;
    event Packet(uint16 indexed srcPort, bytes data);

    function send(uint16 srcPort, bytes calldata data) external {
        if (block.number != lastBlock[srcPort]) {
            lastBlock[srcPort] = block.number;
            usage[srcPort] = 0;
        }
        usage[srcPort] += 1;
        if (usage[srcPort] > MAX_PER_BLOCK) revert SP__TooManyPerPort();
        emit Packet(srcPort, data);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) PORT‑BASED AUTHENTICATION BYPASS
//
//    • Type: authenticate by claimed srcPort ownership
//    • Attack: register(port) then spoof calls
//    • Defense: always use msg.sender for auth
////////////////////////////////////////////////////////////////////////////////
contract AuthByPortVuln {
    mapping(uint16 => address) public portOwner;

    function register(uint16 port) external {
        portOwner[port] = msg.sender;
    }
    function privilegedAction(uint16 port) external view returns (string memory) {
        require(portOwner[port] != address(0), "unregistered");
        // ❌ trusts portOwner but srcPort not checked here
        return portOwner[port] == msg.sender ? "ok" : "denied";
    }
}

contract Attack_AuthByPort {
    AuthByPortVuln public target;
    constructor(AuthByPortVuln _t) { target = _t; }

    function bypass(uint16 port) external view returns (string memory) {
        return target.privilegedAction(port);
    }
}

contract AuthByPortSafe {
    mapping(uint16 => address) public portOwner;
    error SP__NotAllowed();

    function register(uint16 port) external {
        portOwner[port] = msg.sender;
    }
    function privilegedAction(uint16 port) external view returns (string memory) {
        require(portOwner[port] != address(0), "unregistered");
        if (msg.sender != portOwner[port]) revert SP__NotAllowed();
        return "ok";
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) EPHEMERAL PORT EXPIRY
//
//    • Type: lease port forever → stale leases persist
//    • Attack: reuse old leases
//    • Defense: attach TTL and reject expired leases
////////////////////////////////////////////////////////////////////////////////
contract EphemeralPortVuln {
    mapping(uint16 => address) public lease;
    function leasePort(uint16 port) external {
        lease[port] = msg.sender;
    }
    function getLease(uint16 port) external view returns (address) {
        return lease[port];
    }
}

contract Attack_EphemeralPort {
    EphemeralPortVuln public target;
    constructor(EphemeralPortVuln _t) { target = _t; }

    function steal(uint16 port) external view returns (address) {
        return target.getLease(port);
    }
}

contract EphemeralPortSafe {
    struct Lease { address who; uint256 expiry; }
    mapping(uint16 => Lease) public lease;
    error SP__PortExpired();

    function leasePort(uint16 port, uint256 ttl) external {
        lease[port] = Lease(msg.sender, block.timestamp + ttl);
    }
    function getLease(uint16 port) external view returns (address) {
        Lease memory l = lease[port];
        if (block.timestamp > l.expiry) revert SP__PortExpired();
        return l.who;
    }
}
