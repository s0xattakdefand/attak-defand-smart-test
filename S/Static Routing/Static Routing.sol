// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title StaticRoutingSuite.sol
/// @notice On‑chain analogues of four “static routing” patterns: manual route tables,
///         with common pitfalls and hardened defenses.
///
/// Four modules:
///   1) Unauthenticated Route Update  
///   2) Routing Loop Vulnerability  
///   3) Route Update Flood (DoS)  
///   4) Stale Route Expiry  

error SR__NotOwner();
error SR__LoopDetected();
error SR__TooManyUpdates();
error SR__RouteExpired();

////////////////////////////////////////////////////////////////////////
// 1) UNAUTHENTICATED ROUTE UPDATE
//
//   • Vulnerable: anyone may modify the static route table
//   • Attack: unauthorized caller repoints destinations
//   • Defense: only owner may call setRoute()
////////////////////////////////////////////////////////////////////////
contract StaticRoutingVuln {
    mapping(bytes32 => address) public routeTable; // dest → nextHop
    event RouteSet(bytes32 indexed dest, address nextHop);

    function setRoute(bytes32 dest, address nextHop) external {
        // ❌ no access control
        routeTable[dest] = nextHop;
        emit RouteSet(dest, nextHop);
    }
}

contract Attack_StaticRouting1 {
    StaticRoutingVuln public router;
    constructor(StaticRoutingVuln _r) { router = _r; }

    function hijack(bytes32 dest, address evilHop) external {
        // attacker sets a malicious next hop
        router.setRoute(dest, evilHop);
    }
}

contract StaticRoutingSafe {
    mapping(bytes32 => address) public routeTable;
    address public owner;
    event RouteSet(bytes32 indexed dest, address nextHop);

    constructor() { owner = msg.sender; }

    function setRoute(bytes32 dest, address nextHop) external {
        if (msg.sender != owner) revert SR__NotOwner();
        routeTable[dest] = nextHop;
        emit RouteSet(dest, nextHop);
    }
}

////////////////////////////////////////////////////////////////////////
// 2) ROUTING LOOP VULNERABILITY
//
//   • Vulnerable: routes may form cycles → infinite forwarding
//   • Attack: add A→B and B→A, then resolve loops forever
//   • Defense: detect cycles up to a max depth
////////////////////////////////////////////////////////////////////////
contract StaticRoutingVulnLoop {
    mapping(bytes32 => bytes32) public nextHop; // dest → nextDest
    event RouteSet(bytes32 indexed dest, bytes32 nextDest);

    function setRoute(bytes32 dest, bytes32 nextDest) external {
        nextHop[dest] = nextDest;
        emit RouteSet(dest, nextDest);
    }

    function resolve(bytes32 dest) external view returns (bytes32) {
        // ❌ naive: may loop infinitely
        bytes32 cur = dest;
        while (nextHop[cur] != bytes32(0)) {
            cur = nextHop[cur];
        }
        return cur;
    }
}

contract Attack_StaticRoutingLoop {
    StaticRoutingVulnLoop public router;
    constructor(StaticRoutingVulnLoop _r) { router = _r; }

    function createLoop(bytes32 a, bytes32 b) external {
        router.setRoute(a, b);
        router.setRoute(b, a);
    }
}

contract StaticRoutingSafeLoop {
    mapping(bytes32 => bytes32) public nextHop;
    address public owner;
    uint8  public constant MAX_DEPTH = 10;
    event RouteSet(bytes32 indexed dest, bytes32 nextDest);

    constructor() { owner = msg.sender; }

    function setRoute(bytes32 dest, bytes32 nextDest) external {
        if (msg.sender != owner) revert SR__NotOwner();
        // cycle detection
        bytes32 cur = nextDest;
        for (uint8 i = 0; i < MAX_DEPTH; i++) {
            if (cur == dest) revert SR__LoopDetected();
            cur = nextHop[cur];
            if (cur == bytes32(0)) break;
        }
        nextHop[dest] = nextDest;
        emit RouteSet(dest, nextDest);
    }

    function resolve(bytes32 dest) external view returns (bytes32) {
        bytes32 cur = dest;
        for (uint8 i = 0; i < MAX_DEPTH; i++) {
            bytes32 nxt = nextHop[cur];
            if (nxt == bytes32(0)) return cur;
            cur = nxt;
        }
        revert SR__LoopDetected();
    }
}

////////////////////////////////////////////////////////////////////////
// 3) ROUTE UPDATE FLOOD (DoS)
//
//   • Vulnerable: no limit on updates → attacker floods owner with events
//   • Attack: call setRoute() many times to exhaust gas/logs
//   • Defense: rate‑limit updates per block
////////////////////////////////////////////////////////////////////////
contract StaticRoutingVulnFlood {
    mapping(bytes32 => address) public routeTable;
    event RouteSet(bytes32 indexed dest, address nextHop);

    function setRoute(bytes32 dest, address nextHop) external {
        routeTable[dest] = nextHop;
        emit RouteSet(dest, nextHop);
    }
}

contract Attack_StaticRoutingFlood {
    StaticRoutingVulnFlood public router;
    constructor(StaticRoutingVulnFlood _r) { router = _r; }

    function flood(bytes32 destPrefix, uint256 count) external {
        for (uint256 i = 0; i < count; i++) {
            bytes32 dest = keccak256(abi.encodePacked(destPrefix, i));
            router.setRoute(dest, address(0xdead));
        }
    }
}

contract StaticRoutingSafeFlood {
    mapping(bytes32 => address) public routeTable;
    mapping(address => uint256) public updatesThisBlock;
    address public owner;
    uint256 public constant MAX_UPDATES_PER_BLOCK = 5;
    event RouteSet(bytes32 indexed dest, address nextHop);

    constructor() { owner = msg.sender; }

    function setRoute(bytes32 dest, address nextHop) external {
        if (msg.sender != owner) revert SR__NotOwner();
        uint256 blk = block.number;
        if (updatesThisBlock[owner] >= MAX_UPDATES_PER_BLOCK) revert SR__TooManyUpdates();
        updatesThisBlock[owner] += 1;
        // reset counter at new block
        if (block.number > blk) updatesThisBlock[owner] = 1;
        routeTable[dest] = nextHop;
        emit RouteSet(dest, nextHop);
    }
}

////////////////////////////////////////////////////////////////////////
// 4) STALE ROUTE EXPIRY
//
//   • Vulnerable: static routes never expire → traffic may blackhole
//   • Attack: set route and never remove; resolve returns outdated hop
//   • Defense: attach expiry timestamps and drop stale entries on resolve
////////////////////////////////////////////////////////////////////////
contract StaticRoutingVulnStale {
    mapping(bytes32 => address) public routeTable;

    function setRoute(bytes32 dest, address nextHop) external {
        routeTable[dest] = nextHop;
    }

    function resolve(bytes32 dest) external view returns (address) {
        return routeTable[dest];
    }
}

contract StaticRoutingSafeStale {
    struct Route { address nextHop; uint256 expiry; }
    mapping(bytes32 => Route) public routeTable;
    address public owner;
    event RouteSet(bytes32 indexed dest, address nextHop, uint256 expiry);

    constructor() { owner = msg.sender; }

    function setRoute(
        bytes32 dest,
        address nextHop,
        uint256 validForSeconds
    ) external {
        if (msg.sender != owner) revert SR__NotOwner();
        uint256 exp = block.timestamp + validForSeconds;
        routeTable[dest] = Route({ nextHop: nextHop, expiry: exp });
        emit RouteSet(dest, nextHop, exp);
    }

    function resolve(bytes32 dest) external view returns (address) {
        Route memory r = routeTable[dest];
        if (r.expiry < block.timestamp) revert SR__RouteExpired();
        return r.nextHop;
    }
}
