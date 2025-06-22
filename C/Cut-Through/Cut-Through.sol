// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title CutThroughSuite.sol
/// @notice On‑chain analogues of “Cut‑Through” vs. “Store‑and‑Forward” switching patterns:
///   Types: StoreAndForward, CutThrough  
///   AttackTypes: FloodAttack, LoopAttack  
///   DefenseTypes: BufferLimit, LoopPrevention  

enum CutThroughType        { StoreAndForward, CutThrough }
enum CutThroughAttackType  { FloodAttack, LoopAttack }
enum CutThroughDefenseType { BufferLimit, LoopPrevention }

error CT__BufferOverflow();
error CT__LoopDetected();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE SWITCH (Cut‑Through variant)
///
///    • Type: CutThrough  
///    • forwards packets immediately by TTL  
///    • no buffering or loop detection → susceptible to flooding & loops  
///─────────────────────────────────────────────────────────────────────────────
contract CutThroughVuln {
    event PacketForwarded(address indexed from, address indexed to, bytes data, CutThroughAttackType attack);

    /// ❌ forward immediately without buffering or loop check
    function forward(address to, bytes calldata data) external {
        emit PacketForwarded(msg.sender, to, data, CutThroughAttackType.FloodAttack);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB: flood and loop
///
///    • AttackTypes: FloodAttack, LoopAttack  
///─────────────────────────────────────────────────────────────────────────────
contract Attack_CutThrough {
    CutThroughVuln public target;
    constructor(CutThroughVuln _t) { target = _t; }

    /// flood many packets to exhaust resources
    function flood(address to, bytes calldata data, uint256 count) external {
        for (uint i = 0; i < count; i++) {
            target.forward(to, data);
        }
    }

    /// create forwarding loop by spoofing back-and-forth
    function loop(address a, address b, bytes calldata data) external {
        target.forward(a, data);
        target.forward(b, data);
        target.forward(a, data);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE STORE‑AND‑FORWARD SWITCH
///
///    • Type: StoreAndForward  
///    • Defense: BufferLimit – cap buffered packets per sender  
///─────────────────────────────────────────────────────────────────────────────
contract CutThroughSafeBuffer {
    event PacketStored(address indexed sender, address indexed to, bytes data, CutThroughDefenseType defense);
    mapping(address => uint256) public bufferedCount;
    uint256 public constant MAX_BUFFER = 50;

    /// ✅ buffer up to MAX_BUFFER per sender before forwarding
    function storeAndForward(address to, bytes calldata data) external {
        bufferedCount[msg.sender]++;
        if (bufferedCount[msg.sender] > MAX_BUFFER) revert CT__BufferOverflow();
        // in real switch, would enqueue and forward later; here, emit indicating buffered
        emit PacketStored(msg.sender, to, data, CutThroughDefenseType.BufferLimit);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE CUT‑THROUGH WITH LOOP PREVENTION
///
///    • Type: CutThrough  
///    • Defense: LoopPrevention – track hop count to break loops  
///─────────────────────────────────────────────────────────────────────────────
contract CutThroughSafeLoop {
    event PacketForwarded(address indexed from, address indexed to, bytes data, CutThroughDefenseType defense);
    mapping(bytes32 => uint8) public hopCount;
    uint8 public constant MAX_HOPS = 8;

    /// ✅ forward immediately but prevent loops via hop count TTL
    function forward(address to, bytes calldata data, bytes32 packetId) external {
        uint8 hops = hopCount[packetId] + 1;
        if (hops > MAX_HOPS) revert CT__LoopDetected();
        hopCount[packetId] = hops;
        emit PacketForwarded(msg.sender, to, data, CutThroughDefenseType.LoopPrevention);
    }
}
