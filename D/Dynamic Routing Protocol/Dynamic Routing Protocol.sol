// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DynamicRoutingProtocolSuite.sol
/// @notice On‑chain analogues of “Dynamic Routing Protocol” patterns:
///   Types: RIP, OSPF, BGP, EIGRP  
///   AttackTypes: RoutePoisoning, RouteFlapping, ASPathHijack, LSDBFlooding  
///   DefenseTypes: Authentication, TTLCheck, LSDBConsistency, PrefixFiltering  

enum DynamicRoutingProtocolType        { RIP, OSPF, BGP, EIGRP }
enum DynamicRoutingProtocolAttackType  { RoutePoisoning, RouteFlapping, ASPathHijack, LSDBFlooding }
enum DynamicRoutingProtocolDefenseType { Authentication, TTLCheck, LSDBConsistency, PrefixFiltering }

error DRP__NotNeighbor();
error DRP__InvalidAuth();
error DRP__TooManyUpdates();
error DRP__InconsistentDB();
error DRP__PrefixFiltered();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE ROUTER (no checks, accepts any update)
///    • Attack: RoutePoisoning, LSDBFlooding
///─────────────────────────────────────────────────────────────────────────────
contract DynamicRoutingProtocolVuln {
    // destination → (nextHop → metric)
    mapping(address => mapping(address => uint256)) public routes;
    event RouteUpdate(
        address indexed from,
        address indexed dest,
        address nextHop,
        uint256 metric,
        DynamicRoutingProtocolAttackType attack
    );

    function updateRoute(address dest, address nextHop, uint256 metric) external {
        routes[dest][nextHop] = metric;
        emit RouteUpdate(msg.sender, dest, nextHop, metric, DynamicRoutingProtocolAttackType.RoutePoisoning);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB
///    • floods bad updates to poison or flap routes
///─────────────────────────────────────────────────────────────────────────────
contract Attack_DynamicRoutingProtocol {
    DynamicRoutingProtocolVuln public target;
    constructor(DynamicRoutingProtocolVuln _t) { target = _t; }

    function poison(address dest, address evilHop, uint256 badMetric) external {
        target.updateRoute(dest, evilHop, badMetric);
    }

    function flap(address dest, address a, address b, uint256 metric) external {
        // alternate between two nextHops
        target.updateRoute(dest, a, metric);
        target.updateRoute(dest, b, metric);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE ROUTER WITH NEIGHBOR AUTH & RATE LIMIT (Authentication)
///    • Defense: Authentication, RateLimit
///─────────────────────────────────────────────────────────────────────────────
contract DynamicRoutingProtocolSafeAuth {
    DynamicRoutingProtocolType public proto;
    mapping(address => bool) public neighbors;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public updatesInBlock;
    uint256 public constant MAX_UPDATES_PER_BLOCK = 5;
    event RouteUpdate(
        address indexed from,
        address indexed dest,
        address nextHop,
        uint256 metric,
        DynamicRoutingProtocolDefenseType defense
    );

    error DRP__TooManyUpdates();
    error DRP__InvalidAuth();

    constructor(DynamicRoutingProtocolType _p) {
        proto = _p;
        neighbors[msg.sender] = true;
    }

    function setNeighbor(address who, bool ok) external {
        require(neighbors[msg.sender], "only existing neighbor");
        neighbors[who] = ok;
    }

    /// stub authentication: only whitelisted neighbors, rate‑limited
    function updateRoute(address dest, address nextHop, uint256 metric, bytes calldata auth) external {
        if (!neighbors[msg.sender]) revert DRP__NotNeighbor();
        // stub auth check
        if (auth.length == 0) revert DRP__InvalidAuth();

        // rate‑limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            updatesInBlock[msg.sender] = 0;
        }
        updatesInBlock[msg.sender]++;
        if (updatesInBlock[msg.sender] > MAX_UPDATES_PER_BLOCK) revert DRP__TooManyUpdates();

        emit RouteUpdate(msg.sender, dest, nextHop, metric, DynamicRoutingProtocolDefenseType.Authentication);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE OSPF‑LIKE ROUTER WITH TTL CHECK & LSDB CONSISTENCY
///    • Defense: TTLCheck, LSDBConsistency
///─────────────────────────────────────────────────────────────────────────────
contract DynamicRoutingProtocolSafeOSPF {
    mapping(bytes32 => uint16) public lsdbTTL;
    mapping(bytes32 => bytes32) public lsdbHash;
    event LSDBUpdate(
        address indexed from,
        bytes32 indexed linkID,
        uint16 ttl,
        DynamicRoutingProtocolDefenseType defense
    );
    error DRP__InvalidTTL();
    error DRP__InconsistentDB();

    /// stub LSA flood with TTL and consistency check
    function floodLSA(bytes32 linkID, uint16 ttl, bytes32 dbHash) external {
        if (ttl == 0) revert DRP__InvalidTTL();
        // require consistent database hash
        if (lsdbHash[linkID] != bytes32(0) && lsdbHash[linkID] != dbHash) revert DRP__InconsistentDB();
        lsdbTTL[linkID]  = ttl;
        lsdbHash[linkID] = dbHash;
        emit LSDBUpdate(msg.sender, linkID, ttl, DynamicRoutingProtocolDefenseType.LSDBConsistency);
    }

    /// decrement TTL stub
    function tick(bytes32 linkID) external {
        if (lsdbTTL[linkID] > 0) lsdbTTL[linkID]--;
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 5) SAFE BGP‑LIKE ROUTER WITH PREFIX FILTERING
///    • Defense: PrefixFiltering
///─────────────────────────────────────────────────────────────────────────────
contract DynamicRoutingProtocolSafeBGP {
    mapping(address => mapping(bytes32 => bool)) public allowedPrefixes; // peer → prefix → allowed
    event PrefixAnnounce(
        address indexed peer,
        bytes32 indexed prefix,
        DynamicRoutingProtocolDefenseType defense
    );
    error DRP__PrefixFiltered();

    /// owner or admin populates prefix filters per neighbor
    function setAllowedPrefix(address peer, bytes32 prefix, bool ok) external {
        // assume contract owner for simplicity
        require(msg.sender == address(this) || msg.sender == tx.origin, "only admin");
        allowedPrefixes[peer][prefix] = ok;
    }

    /// stub announce with prefix filter
    function announcePrefix(bytes32 prefix) external {
        if (!allowedPrefixes[msg.sender][prefix]) revert DRP__PrefixFiltered();
        emit PrefixAnnounce(msg.sender, prefix, DynamicRoutingProtocolDefenseType.PrefixFiltering);
    }
}
