// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DistanceVectorSuite.sol
/// @notice On‑chain analogues of “Distance Vector” routing patterns:
///   Types: Basic, SplitHorizon, PoisonReverse  
///   AttackTypes: CountToInfinity, RoutingLoop, RoutePoisoning  
///   DefenseTypes: SplitHorizon, PoisonReverse, HoldDownTimer, AuthenticatedUpdate  

enum DistanceVectorType         { Basic, SplitHorizon, PoisonReverse }
enum DistanceVectorAttackType   { CountToInfinity, RoutingLoop, RoutePoisoning }
enum DistanceVectorDefenseType  { SplitHorizon, PoisonReverse, HoldDownTimer, AuthenticatedUpdate }

error DV__InvalidMetric();
error DV__LoopDetected();
error DV__NotNeighbor();
error DV__TooFrequent();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE DISTANCE VECTOR (Basic)
///
///    • accepts any update from any node, no loop prevention  
///    • Attack: Count‑to‑Infinity, RoutingLoop
///─────────────────────────────────────────────────────────────────────────────
contract DistanceVectorVuln {
    // dest → (next hop → metric)
    mapping(address => mapping(address => uint256)) public table;
    event RouteUpdated(
        address indexed from,
        address indexed dest,
        address nextHop,
        uint256 metric,
        DistanceVectorAttackType attack
    );

    /// ❌ no validation or loop prevention
    function updateRoute(address dest, address nextHop, uint256 metric) external {
        table[dest][nextHop] = metric;
        emit RouteUpdated(msg.sender, dest, nextHop, metric, DistanceVectorAttackType.CountToInfinity);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB
///
///    • floods bad routes causing count‑to‑infinity or loops
///─────────────────────────────────────────────────────────────────────────────
contract Attack_DistanceVector {
    DistanceVectorVuln public target;
    constructor(DistanceVectorVuln _t) { target = _t; }

    /// flood with ever‑increasing metrics for a victim dest
    function floodPoison(address dest, address nextHop, uint256 startMetric, uint256 count) external {
        for (uint256 i = 0; i < count; i++) {
            target.updateRoute(dest, nextHop, startMetric + i);
        }
    }

    /// create a simple loop by swapping nextHops
    function causeLoop(address dest, address a, address b) external {
        target.updateRoute(dest, a, 1);
        target.updateRoute(dest, b, 1);
        // a learns route via b, b via a → loop
        target.updateRoute(dest, b, 2);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE DISTANCE VECTOR WITH SPLIT‑HORIZON + POISON‑REVERSE
///
///    • Defense: SplitHorizon – ignore updates for routes learned via the sender  
///               PoisonReverse – advertise infinite metric back to neighbor
///─────────────────────────────────────────────────────────────────────────────
contract DistanceVectorSafe {
    mapping(address => mapping(address => uint256)) public table;
    // dest → current best nextHop
    mapping(address => address) public bestHop;
    event RouteUpdated(
        address indexed from,
        address indexed dest,
        address nextHop,
        uint256 metric,
        DistanceVectorDefenseType defense
    );

    /// ✅ SplitHorizon + PoisonReverse
    function updateRoute(address dest, address nextHop, uint256 metric) external {
        // SplitHorizon: if we route to dest via msg.sender, ignore
        if (bestHop[dest] == msg.sender) {
            // PoisonReverse: advertise infinite metric back
            table[dest][msg.sender] = type(uint256).max;
            emit RouteUpdated(msg.sender, dest, msg.sender, type(uint256).max, DistanceVectorDefenseType.PoisonReverse);
            return;
        }
        // accept and record
        table[dest][msg.sender] = metric;
        // choose best
        if (bestHop[dest] == address(0) || metric < table[dest][bestHop[dest]]) {
            bestHop[dest] = msg.sender;
        }
        emit RouteUpdated(msg.sender, dest, msg.sender, metric, DistanceVectorDefenseType.SplitHorizon);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) ADVANCED SAFE WITH AUTHENTICATED UPDATES + HOLD‑DOWN TIMERS
///
///    • Defense: AuthenticatedUpdate – only whitelisted neighbors  
///               HoldDownTimer – reject flapping updates too frequently
///─────────────────────────────────────────────────────────────────────────────
contract DistanceVectorSafeAdvanced {
    address public owner;
    mapping(address => bool)         public neighbors;
    mapping(address => uint256)      public lastUpdateBlock;
    mapping(address => mapping(address => uint256)) public table;
    mapping(address => address)      public bestHop;
    uint256 public constant HOLD_DOWN_BLOCKS = 5;

    event RouteUpdated(
        address indexed from,
        address indexed dest,
        address nextHop,
        uint256 metric,
        DistanceVectorDefenseType defense
    );

    error DV__NotNeighbor();
    error DV__TooFrequent();

    constructor() {
        owner = msg.sender;
    }

    /// owner manages trusted neighbors
    function setNeighbor(address who, bool ok) external {
        require(msg.sender == owner, "only owner");
        neighbors[who] = ok;
    }

    /// ✅ only authenticated neighbors + hold‑down timer
    function updateRoute(address dest, uint256 metric) external {
        if (!neighbors[msg.sender]) revert DV__NotNeighbor();
        if (block.number < lastUpdateBlock[msg.sender] + HOLD_DOWN_BLOCKS) revert DV__TooFrequent();

        table[dest][msg.sender] = metric;
        // choose best
        if (bestHop[dest] == address(0) || metric < table[dest][bestHop[dest]]) {
            bestHop[dest] = msg.sender;
        }

        lastUpdateBlock[msg.sender] = block.number;
        emit RouteUpdated(msg.sender, dest, msg.sender, metric, DistanceVectorDefenseType.AuthenticatedUpdate);
    }

    /// view current best metric and next hop for a dest
    function getRoute(address dest) external view returns (address nextHop, uint256 metric) {
        nextHop = bestHop[dest];
        metric = table[dest][nextHop];
    }
}
