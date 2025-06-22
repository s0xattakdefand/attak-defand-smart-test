// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title TopologySuite.sol
/// @notice On‑chain analogues of “Network Topology” patterns:
///   Types: Bus, Star, Ring, Mesh  
///   AttackTypes: SinglePointFailure, BroadcastStorm, PartitionAttack, SpoofLink  
///   DefenseTypes: Redundancy, RateLimit, ConnectivityCheck, Authenticated  

enum TopologyType          { Bus, Star, Ring, Mesh }
enum TopologyAttackType    { SinglePointFailure, BroadcastStorm, PartitionAttack, SpoofLink }
enum TopologyDefenseType   { Redundancy, RateLimit, ConnectivityCheck, Authenticated }

error TP__NotOwner();
error TP__AlreadyNeighbor();
error TP__NoRedundancy();
error TP__TooManyBroadcasts();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE TOPOLOGY (no controls, single point failure)
///    • anyone may link nodes and broadcast freely
///    • Attack: disconnect the hub to break the bus/star
///─────────────────────────────────────────────────────────────────────────────
contract TopologyVuln {
    mapping(address => address[]) public neighbors;
    TopologyType public topology;

    constructor(TopologyType t) {
        topology = t;
    }

    /// ❌ anyone may link two nodes
    function connect(address a, address b) external {
        neighbors[a].push(b);
        neighbors[b].push(a);
    }

    /// ❌ anyone may broadcast without limit
    event Message(address indexed from, address indexed to, bytes data, TopologyAttackType attack);
    function broadcast(address from, bytes calldata data) external {
        for (uint i; i < neighbors[from].length; i++) {
            address to = neighbors[from][i];
            emit Message(from, to, data, TopologyAttackType.BroadcastStorm);
        }
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB: broadcast storm and single‑point disconnection
///─────────────────────────────────────────────────────────────────────────────
contract Attack_Topology {
    TopologyVuln public net;
    constructor(TopologyVuln _net) { net = _net; }

    /// spam broadcasts from a given node
    function storm(address from, bytes calldata data, uint count) external {
        for (uint i; i < count; i++) {
            net.broadcast(from, data);
        }
    }

    /// sever the hub connection in a bus/star
    function sever(address hub, address leaf) external {
        // not actual removal; illustrates how removing linkage off‑chain severs communication
        // in practice attacker would overwrite storage slot directly if unprotected
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE TOPOLOGY (authenticated, rate‑limited)
///    • only owner may connect
///    • broadcasts capped per block
///─────────────────────────────────────────────────────────────────────────────
contract TopologySafe {
    mapping(address => address[]) public neighbors;
    address public owner;
    TopologyType public topology;
    mapping(address => uint) public lastBlock;
    mapping(address => uint) public broadcastCount;
    uint public constant MAX_BCAST_PER_BLOCK = 10;

    event Message(address indexed from, address indexed to, bytes data, TopologyDefenseType defense);

    constructor(TopologyType t) {
        owner = msg.sender;
        topology = t;
    }

    function connect(address a, address b) external {
        if (msg.sender != owner) revert TP__NotOwner();
        neighbors[a].push(b);
        neighbors[b].push(a);
    }

    function broadcast(address from, bytes calldata data) external {
        // rate‑limit broadcasts per node
        if (block.number != lastBlock[from]) {
            lastBlock[from] = block.number;
            broadcastCount[from] = 0;
        }
        broadcastCount[from]++;
        if (broadcastCount[from] > MAX_BCAST_PER_BLOCK) revert TP__TooManyBroadcasts();

        for (uint i; i < neighbors[from].length; i++) {
            emit Message(from, neighbors[from][i], data, TopologyDefenseType.RateLimit);
        }
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) RESILIENT TOPOLOGY (redundancy & connectivity checks)
///    • only owner may link
///    • enforces each node has ≥2 neighbors (no single point failure)
///─────────────────────────────────────────────────────────────────────────────
contract TopologySafeResilient {
    mapping(address => address[]) public neighbors;
    address public owner;
    TopologyType public topology;

    event Connected(address indexed a, address indexed b, TopologyDefenseType defense);

    constructor(TopologyType t) {
        owner = msg.sender;
        topology = t;
    }

    function connect(address a, address b) external {
        if (msg.sender != owner) revert TP__NotOwner();
        // temporarily add
        neighbors[a].push(b);
        neighbors[b].push(a);
        // enforce redundancy: each node must have at least two neighbors
        if (neighbors[a].length < 2 || neighbors[b].length < 2) revert TP__NoRedundancy();
        emit Connected(a, b, TopologyDefenseType.Redundancy);
    }

    /// simple reachability check: returns true if path exists via BFS up to depth 3
    function isConnected(address src, address dst) external view returns (bool) {
        address;
        frontier[0] = src;
        for (uint depth; depth < 3; depth++) {
            uint len = frontier.length;
            address[] memory next = new address[](len * 2);
            uint idx;
            for (uint i; i < len; i++) {
                address u = frontier[i];
                for (uint j; j < neighbors[u].length; j++) {
                    address v = neighbors[u][j];
                    if (v == dst) return true;
                    next[idx++] = v;
                }
            }
            frontier = new address[](idx);
            for (uint k; k < idx; k++) frontier[k] = next[k];
        }
        return false;
    }
}
