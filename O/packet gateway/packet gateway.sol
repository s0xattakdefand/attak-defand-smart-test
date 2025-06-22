// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title PacketGatewaySuite.sol
/// @notice On-chain analogues of “Packet Gateway” network patterns:
///   Types: NAT, Firewall, VPN, LoadBalancer  
///   AttackTypes: PacketDropping, Spoofing, Flooding, Tampering  
///   DefenseTypes: ACL, RateLimit, DeepInspection, Encryption  

enum PacketGatewayType        { NAT, Firewall, VPN, LoadBalancer }
enum PacketGatewayAttackType  { PacketDropping, Spoofing, Flooding, Tampering }
enum PacketGatewayDefenseType { ACL, RateLimit, DeepInspection, Encryption }

error PG__NotAllowed();
error PG__TooMany();
error PG__InvalidPacket();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE GATEWAY
//
//    • ❌ no controls: any packet forwarded or dropped arbitrarily → Tampering, Dropping
////////////////////////////////////////////////////////////////////////////////
contract PacketGatewayVuln {
    event PacketHandled(
        address indexed from,
        address indexed to,
        bytes             packet,
        PacketGatewayType        gtype,
        PacketGatewayAttackType  attack
    );

    function forward(address to, PacketGatewayType gtype, bytes calldata packet) external {
        // no checks: attacker can spoof or drop
        emit PacketHandled(msg.sender, to, packet, gtype, PacketGatewayAttackType.Tampering);
    }

    function drop(address to, PacketGatewayType gtype, bytes calldata packet) external {
        emit PacketHandled(msg.sender, to, packet, gtype, PacketGatewayAttackType.PacketDropping);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//    • simulates flooding and spoofing
////////////////////////////////////////////////////////////////////////////////
contract Attack_PacketGateway {
    PacketGatewayVuln public target;

    constructor(PacketGatewayVuln _t) {
        target = _t;
    }

    function flood(address to, PacketGatewayType gtype, bytes calldata packet, uint256 times) external {
        for (uint256 i = 0; i < times; i++) {
            target.forward(to, gtype, packet);
        }
    }

    function spoof(address victim, PacketGatewayType gtype, bytes calldata packet) external {
        // pretend to be victim
        target.forward(victim, gtype, packet);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACL
//
//    • ✅ Defense: ACL – only whitelisted endpoints may send/receive
////////////////////////////////////////////////////////////////////////////////
contract PacketGatewaySafeACL {
    mapping(address => bool) public allowed;
    event PacketHandled(
        address indexed from,
        address indexed to,
        PacketGatewayType        gtype,
        PacketGatewayDefenseType defense
    );

    error PG__NotAllowed();

    constructor() {
        allowed[msg.sender] = true;
    }

    function setAllowed(address peer, bool ok) external {
        require(allowed[msg.sender], "only admin");
        allowed[peer] = ok;
    }

    function forward(address to, PacketGatewayType gtype, bytes calldata /*packet*/) external {
        if (!allowed[msg.sender] || !allowed[to]) revert PG__NotAllowed();
        emit PacketHandled(msg.sender, to, gtype, PacketGatewayDefenseType.ACL);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH RATE-LIMITING
//
//    • ✅ Defense: RateLimit – cap forwards per block per sender
////////////////////////////////////////////////////////////////////////////////
contract PacketGatewaySafeRateLimit {
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public sendsInBlock;
    uint256 public constant MAX_SENDS = 10;

    event PacketHandled(
        address indexed from,
        address indexed to,
        PacketGatewayType        gtype,
        PacketGatewayDefenseType defense
    );

    error PG__TooMany();

    function forward(address to, PacketGatewayType gtype, bytes calldata /*packet*/) external {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            sendsInBlock[msg.sender] = 0;
        }
        sendsInBlock[msg.sender]++;
        if (sendsInBlock[msg.sender] > MAX_SENDS) revert PG__TooMany();
        emit PacketHandled(msg.sender, to, gtype, PacketGatewayDefenseType.RateLimit);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH DEEP INSPECTION & ENCRYPTION
//
//    • ✅ Defense: DeepInspection – simple payload check stub  
//               Encryption – require encrypted packets
////////////////////////////////////////////////////////////////////////////////
contract PacketGatewaySafeAdvanced {
    mapping(address => bool) public allowedEncryption; // who can decrypt/re-encrypt
    event PacketHandled(
        address indexed from,
        address indexed to,
        PacketGatewayType        gtype,
        PacketGatewayDefenseType defense
    );

    error PG__InvalidPacket();
    error PG__NotAllowed();

    constructor() {
        allowedEncryption[msg.sender] = true;
    }

    function setEncryptionAllowed(address who, bool ok) external {
        require(allowedEncryption[msg.sender], "only admin");
        allowedEncryption[who] = ok;
    }

    function forward(address to, PacketGatewayType gtype, bytes calldata packet, bytes calldata /*sig*/) external {
        if (!allowedEncryption[msg.sender]) revert PG__NotAllowed();
        // DeepInspection stub: require packet non-empty and starts with 0xAA
        if (packet.length == 0 || packet[0] != 0xAA) revert PG__InvalidPacket();
        emit PacketHandled(msg.sender, to, gtype, PacketGatewayDefenseType.DeepInspection);
        // Encryption defense assumed: packet already encrypted off-chain
    }
}
