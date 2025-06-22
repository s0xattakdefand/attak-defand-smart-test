// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title SplitHorizonSuite.sol
/// @notice Four “Split Horizon” routing patterns:  
///   1) No Split Horizon (Vulnerable)  
///   2) Loop Attack  
///   3) Split Horizon Safe  
///   4) Poison Reverse Safe  

interface IRouter {
    /// @param origin     the peer who originally advertised the route  
    /// @param route      the route identifier  
    /// @param reachable  true if reachable, false if poisoned  
    function receiveRoute(address origin, bytes32 route, bool reachable) external;
}

////////////////////////////////////////////////////////////////////////
// 1) NO SPLIT HORIZON (VULNERABLE)
//    • Type: full broadcast of learned routes to all neighbors
//    • Attack: routes are advertised back to origin, enabling loops
//    • Defense: see next modules
////////////////////////////////////////////////////////////////////////
contract RouterVuln {
    address[] public neighbors;
    mapping(bytes32 => bool) public known;

    function addNeighbor(address peer) external {
        neighbors.push(peer);
    }

    /// advertise a new route to all neighbors, including the origin later on
    function announce(bytes32 route) public {
        known[route] = true;
        for (uint i = 0; i < neighbors.length; i++) {
            IRouter(neighbors[i]).receiveRoute(msg.sender, route, true);
        }
    }

    /// receive a route from a neighbor and rebroadcast it
    function receiveRoute(address /* origin */, bytes32 route, bool reachable) external {
        if (reachable && !known[route]) {
            // learn and rebroadcast, without split‑horizon check
            known[route] = true;
            announce(route);
        }
    }
}

////////////////////////////////////////////////////////////////////////
// 2) LOOP ATTACK
//    • Type: set up two vulnerable routers as neighbors and announce
//    • Attack: infinite back‑and‑forth advertisement until gas/depth exhausted
////////////////////////////////////////////////////////////////////////
contract Attack_RoutingLoop {
    RouterVuln public A;
    RouterVuln public B;

    constructor(RouterVuln _A, RouterVuln _B) {
        A = _A;
        B = _B;
    }

    function setupAndExploit(bytes32 route) external {
        // form bidirectional neighbor links
        A.addNeighbor(address(B));
        B.addNeighbor(address(A));
        // kick off the loop
        A.announce(route);
    }
}

////////////////////////////////////////////////////////////////////////
// 3) SPLIT HORIZON SAFE
//    • Type: do not advertise a route back to the neighbor from which it came
//    • Defense: record origin of each route and exclude that peer
////////////////////////////////////////////////////////////////////////
contract RouterSafe {
    address[]               public neighbors;
    mapping(bytes32 => bool) public known;
    mapping(bytes32 => address) public originOf;

    function addNeighbor(address peer) external {
        neighbors.push(peer);
    }

    /// advertise a new route (origin = self)
    function announce(bytes32 route) public {
        known[route]      = true;
        originOf[route]   = msg.sender;
        _broadcast(route);
    }

    /// receive a route and rebroadcast it, excluding the peer it came from
    function receiveRoute(address origin, bytes32 route, bool reachable) external {
        if (reachable && !known[route]) {
            known[route]    = true;
            originOf[route] = origin;
            _broadcast(route);
        }
    }

    function _broadcast(bytes32 route) internal {
        address orig = originOf[route];
        for (uint i = 0; i < neighbors.length; i++) {
            address peer = neighbors[i];
            if (peer != orig) {
                IRouter(peer).receiveRoute(address(this), route, true);
            }
        }
    }
}

////////////////////////////////////////////////////////////////////////
// 4) POISON REVERSE SAFE
//    • Type: instead of suppressing advertisement, send “unreachable” back
//    • Defense: advertise false reachability to the origin peer
////////////////////////////////////////////////////////////////////////
contract RouterPoisonReverseSafe {
    address[]               public neighbors;
    mapping(bytes32 => bool) public known;
    mapping(bytes32 => address) public originOf;

    function addNeighbor(address peer) external {
        neighbors.push(peer);
    }

    /// advertise a new route (origin = self)
    function announce(bytes32 route) public {
        known[route]    = true;
        originOf[route] = msg.sender;
        _broadcast(route);
    }

    /// receive and rebroadcast with poison‑reverse to the origin
    function receiveRoute(address origin, bytes32 route, bool reachable) external {
        if (reachable && !known[route]) {
            known[route]    = true;
            originOf[route] = origin;
            _broadcast(route);
        }
    }

    function _broadcast(bytes32 route) internal {
        address orig = originOf[route];
        for (uint i = 0; i < neighbors.length; i++) {
            address peer = neighbors[i];
            bool reach = true;
            if (peer == orig) {
                // poison reverse: advertise unreachable to the origin
                reach = false;
            }
            IRouter(peer).receiveRoute(address(this), route, reach);
        }
    }
}
