// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title BackscatterChannelSuite.sol
/// @notice On-chain analogues of “Backscatter Channel” patterns:
///   Types: Passive, Active, Inband, OutOfBand  
///   AttackTypes: Reflection, Amplification, Spoofing, Replay  
///   DefenseTypes: IngressFiltering, EgressFiltering, PacketValidation, RateLimit  

enum BackscatterChannelType          { Passive, Active, Inband, OutOfBand }
enum BackscatterChannelAttackType    { Reflection, Amplification, Spoofing, Replay }
enum BackscatterChannelDefenseType   { IngressFiltering, EgressFiltering, PacketValidation, RateLimit }

error BC__NotAllowed();
error BC__InvalidPacket();
error BC__TooManyRequests();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE CHANNEL (no filtering, open to spoofed traffic)
///
///    • Attack: Reflection, Amplification
///─────────────────────────────────────────────────────────────────────────────
contract BackscatterChannelVuln {
    event BackscatterEmitted(
        address indexed from,
        address indexed victim,
        BackscatterChannelType   ctype,
        bytes                    packet,
        BackscatterChannelAttackType attack
    );

    /// ❌ anyone may emit backscatter for any victim
    function emitBackscatter(address victim, BackscatterChannelType ctype, bytes calldata packet) external {
        emit BackscatterEmitted(msg.sender, victim, ctype, packet, BackscatterChannelAttackType.Reflection);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB
///
///    • simulates spoofing and replay of backscatter packets
///─────────────────────────────────────────────────────────────────────────────
contract Attack_BackscatterChannel {
    BackscatterChannelVuln public target;
    bytes public lastPacket;

    constructor(BackscatterChannelVuln _t) {
        target = _t;
    }

    /// capture a packet off-chain
    function capture(bytes calldata packet) external {
        lastPacket = packet;
    }

    /// replay the captured packet to victim
    function replay(address victim, BackscatterChannelType ctype) external {
        target.emitBackscatter(victim, ctype, lastPacket);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE CHANNEL WITH INGRESS FILTERING
///
///    • Defense: IngressFiltering – only whitelist known reflectors
///─────────────────────────────────────────────────────────────────────────────
contract BackscatterChannelSafeIngress {
    mapping(address => bool) public allowedReflector;
    event BackscatterEmitted(
        address indexed from,
        address indexed victim,
        BackscatterChannelType   ctype,
        bytes                    packet,
        BackscatterChannelDefenseType defense
    );

    error BC__NotAllowed();

    /// owner configures allowed reflectors
    address public owner;
    constructor() { owner = msg.sender; }

    function setReflector(address reflector, bool ok) external {
        require(msg.sender == owner, "only owner");
        allowedReflector[reflector] = ok;
    }

    /// only allowed reflectors may emit backscatter
    function emitBackscatter(address victim, BackscatterChannelType ctype, bytes calldata packet) external {
        if (!allowedReflector[msg.sender]) revert BC__NotAllowed();
        emit BackscatterEmitted(msg.sender, victim, ctype, packet, BackscatterChannelDefenseType.IngressFiltering);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE CHANNEL WITH EGRESS FILTERING & PACKET VALIDATION
///
///    • Defense: EgressFiltering – only to known victims  
///               PacketValidation – simple length check
///─────────────────────────────────────────────────────────────────────────────
contract BackscatterChannelSafeEgress {
    mapping(address => bool) public allowedVictim;
    event BackscatterEmitted(
        address indexed from,
        address indexed victim,
        BackscatterChannelType   ctype,
        bytes                    packet,
        BackscatterChannelDefenseType defense
    );

    error BC__NotAllowed();
    error BC__InvalidPacket();

    /// owner configures allowed victims
    address public owner;
    constructor() { owner = msg.sender; }

    function setVictim(address victim, bool ok) external {
        require(msg.sender == owner, "only owner");
        allowedVictim[victim] = ok;
    }

    /// validate packet and restrict destination
    function emitBackscatter(address victim, BackscatterChannelType ctype, bytes calldata packet) external {
        if (!allowedVictim[victim]) revert BC__NotAllowed();
        if (packet.length == 0 || packet.length > 1024) revert BC__InvalidPacket();
        emit BackscatterEmitted(msg.sender, victim, ctype, packet, BackscatterChannelDefenseType.PacketValidation);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 5) SAFE ADVANCED CHANNEL WITH RATE-LIMITING
///
///    • Defense: RateLimit – cap backscatter emissions per block per reflector
///─────────────────────────────────────────────────────────────────────────────
contract BackscatterChannelSafeAdvanced {
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public emitsInBlock;
    uint256 public constant MAX_EMITS_PER_BLOCK = 5;

    event BackscatterEmitted(
        address indexed from,
        address indexed victim,
        BackscatterChannelType   ctype,
        bytes                    packet,
        BackscatterChannelDefenseType defense
    );

    error BC__TooManyRequests();

    /// rate-limit per reflector
    function emitBackscatter(address victim, BackscatterChannelType ctype, bytes calldata packet) external {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            emitsInBlock[msg.sender] = 0;
        }
        emitsInBlock[msg.sender]++;
        if (emitsInBlock[msg.sender] > MAX_EMITS_PER_BLOCK) revert BC__TooManyRequests();

        emit BackscatterEmitted(msg.sender, victim, ctype, packet, BackscatterChannelDefenseType.RateLimit);
    }
}
