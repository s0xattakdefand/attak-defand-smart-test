// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DisruptionSuite.sol
/// @notice On‑chain analogues of “Disruption” attack and defense patterns:
///   Types: ServiceDisruption, DataDisruption, NetworkDisruption  
///   AttackTypes: Jamming, Blackhole, PacketDrop  
///   DefenseTypes: Redundancy, Diversion, RateLimit, Monitoring  

enum DisruptionType        { ServiceDisruption, DataDisruption, NetworkDisruption }
enum DisruptionAttackType  { Jamming, Blackhole, PacketDrop }
enum DisruptionDefenseType { Redundancy, Diversion, RateLimit, Monitoring }

error DSP__TooMany();
error DSP__NotAllowed();
error DSP__Detected();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE NODE (no defenses)
///
///    • any node can drop or jam messages  
///    • Attack: Jamming, PacketDrop
///─────────────────────────────────────────────────────────────────────────────
contract DisruptionVuln {
    event MessageForwarded(
        address indexed from,
        address indexed to,
        bytes      data,
        DisruptionAttackType attack
    );

    function forward(address to, bytes calldata data) external {
        // ❌ simply emit, no check; attacker can jam by not forwarding
        emit MessageForwarded(msg.sender, to, data, DisruptionAttackType.PacketDrop);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB
///
///    • simulates a blackhole drop or jamming by calling vuln with empty data
///─────────────────────────────────────────────────────────────────────────────
contract Attack_Disruption {
    DisruptionVuln public target;
    constructor(DisruptionVuln _t) { target = _t; }

    function jam(address to) external {
        // attacker floods with empty frames (jamming)
        target.forward(to, "");
    }

    function blackhole(address to, bytes calldata data) external {
        // attacker pretends to forward but drops data
        // no call to forward => blackhole
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE FORWARDER WITH REDUNDANCY
///
///    • Defense: Redundancy – send via N parallel paths
///─────────────────────────────────────────────────────────────────────────────
contract DisruptionSafeRedundancy {
    event MessageForwarded(
        address indexed from,
        address indexed to,
        bytes      data,
        DisruptionDefenseType defense
    );

    function forward(address[] calldata paths, bytes calldata data) external {
        for (uint i = 0; i < paths.length; i++) {
            // in a real network would send along each path
            emit MessageForwarded(msg.sender, paths[i], data, DisruptionDefenseType.Redundancy);
        }
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE FORWARDER WITH RATE‑LIMIT & MONITORING
///
///    • Defense: RateLimit – cap forwards per block  
///               Monitoring – emit alert on excessive failures
///─────────────────────────────────────────────────────────────────────────────
contract DisruptionSafeMonitor {
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public countInBlock;
    uint256 public constant MAX_PER_BLOCK = 10;

    event MessageForwarded(
        address indexed from,
        address indexed to,
        bytes      data,
        DisruptionDefenseType defense
    );
    event DisruptionDetected(
        address indexed who,
        address indexed to,
        string     reason,
        DisruptionDefenseType defense
    );

    error DSP__TooMany();

    function forward(address to, bytes calldata data, bool pathHealthy) external {
        // rate‑limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_PER_BLOCK) revert DSP__TooMany();

        // monitoring: detect path failure
        if (!pathHealthy) {
            emit DisruptionDetected(msg.sender, to, "path failure", DisruptionDefenseType.Monitoring);
            // optionally divert or drop
            return;
        }

        emit MessageForwarded(msg.sender, to, data, DisruptionDefenseType.RateLimit);
    }
}
