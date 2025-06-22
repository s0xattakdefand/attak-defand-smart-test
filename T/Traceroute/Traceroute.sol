// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title TraceRouteSuite.sol
/// @notice On‑chain analogues of “Traceroute” patterns with common pitfalls
///         and hardened defenses.

enum TraceRouteType         { ICMP, UDP, TCP }
enum TraceRouteAttackType   { HopSpoof, TTLManipulation, FloodTrace }
enum TraceRouteDefenseType  { VerifySource, TTLCheck, RateLimit }

error TR__SpoofDetected();
error TR__BadTTL();
error TR__TooManyRequests();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE TRACEROUTE LOGGER
///    • Type: any caller may log any hop with any TTL
///    • Attack: spoof hops or TTL to fake path
///─────────────────────────────────────────────────────────────────────────────
contract TraceRouteVuln {
    event HopLogged(
        address indexed tracer,
        address indexed hop,
        TraceRouteType    proto,
        uint8             ttl,
        TraceRouteAttackType attack
    );

    /// anyone may log a hop for any tracer, protocol, and TTL
    function logHop(
        address tracer,
        address hop,
        TraceRouteType proto,
        uint8 ttl
    ) external {
        emit HopLogged(tracer, hop, proto, ttl, TraceRouteAttackType.HopSpoof);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB
///    • Demonstrates spoofing hops and TTL manipulation
///─────────────────────────────────────────────────────────────────────────────
contract Attack_TraceRoute {
    TraceRouteVuln public target;

    constructor(TraceRouteVuln _t) {
        target = _t;
    }

    /// attacker injects fake hops up to a given TTL
    function spoofPath(address tracer, TraceRouteType proto, uint8 maxTtl) external {
        for (uint8 ttl = 1; ttl <= maxTtl; ttl++) {
            // spoof hop as attacker with manipulated TTL
            target.logHop(tracer, msg.sender, proto, ttl);
        }
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE TRACEROUTE LOGGER
///    • Defense: VerifySource (require msg.sender == hop) + TTLCheck (monotonic)
///─────────────────────────────────────────────────────────────────────────────
contract TraceRouteSafe {
    event HopLogged(
        address indexed tracer,
        address indexed hop,
        TraceRouteType    proto,
        uint8             ttl,
        TraceRouteDefenseType defense
    );

    // track last TTL logged per tracer
    mapping(address => uint8) public lastTtl;

    /// only the node itself may log its hop, and TTL must increment by 1
    function logHop(
        address tracer,
        TraceRouteType proto,
        uint8 ttl
    ) external {
        // verify source: msg.sender is actual hop
        address hop = msg.sender;
        // TTL must be last + 1 (start at 1)
        uint8 expected = lastTtl[tracer] + 1;
        if (ttl != expected) revert TR__BadTTL();
        lastTtl[tracer] = ttl;
        emit HopLogged(tracer, hop, proto, ttl, TraceRouteDefenseType.TTLCheck);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) RATE‑LIMITED TRACEROUTE LOGGER
///    • Defense: RateLimit per tracer per block
///─────────────────────────────────────────────────────────────────────────────
contract TraceRouteSafeRateLimit {
    event HopLogged(
        address indexed tracer,
        address indexed hop,
        TraceRouteType    proto,
        uint8             ttl,
        TraceRouteDefenseType defense
    );

    mapping(address => uint8)  public lastTtl;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint16) public countInBlock;

    uint16 public constant MAX_PER_BLOCK = 20;

    /// only msg.sender may log itself, TTL must increment, and limited per block
    function logHop(
        address tracer,
        TraceRouteType proto,
        uint8 ttl
    ) external {
        if (tracer != tx.origin) {
            // require tracer is origin of trace request
            revert TR__SpoofDetected();
        }
        // rate‑limit per tracer per block
        if (block.number != lastBlock[tracer]) {
            lastBlock[tracer] = block.number;
            countInBlock[tracer] = 0;
        }
        countInBlock[tracer]++;
        if (countInBlock[tracer] > MAX_PER_BLOCK) revert TR__TooManyRequests();

        // TTL monotonic check
        uint8 expected = lastTtl[tracer] + 1;
        if (ttl != expected) revert TR__BadTTL();
        lastTtl[tracer] = ttl;

        emit HopLogged(tracer, msg.sender, proto, ttl, TraceRouteDefenseType.RateLimit);
    }
}
