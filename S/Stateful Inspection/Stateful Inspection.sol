// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title StatefulInspectionSuite.sol
/// @notice Four “Stateful Inspection” patterns, each with a vulnerable module,
///         a demo attack, and a hardened safe module enforcing proper session tracking.

error SI__NoSession();
error SI__BadState();
error SI__SessionExpired();
error SI__FloodDetected();

///─────────────────────────────────────────────────────────────────────────────
/// 1) STATELESS FILTER (NO CONNECTION TRACKING)
///─────────────────────────────────────────────────────────────────────────────
contract StatelessFilterVuln {
    mapping(address => bool) public allowed;

    /// ❌ anyone can flip allowed on/off
    function setAllowed(address peer, bool ok) external {
        allowed[peer] = ok;
    }

    /// ❌ no per‑session state: once allowed, can send anytime
    function send(address to, bytes calldata data) external returns (bool) {
        require(allowed[msg.sender], "not allowed");
        (bool ok, ) = to.call(data);
        return ok;
    }
}

contract Attack_StatelessFilter {
    StatelessFilterVuln public fw;
    constructor(StatelessFilterVuln _fw) { fw = _fw; }

    function bypass(address victim, bytes calldata payload) external {
        // if victim has ever allowed attacker, they can call send at will
        fw.send(victim, payload);
    }
}

contract StatefulFilterSafe {
    enum State { None, Established }
    mapping(address => mapping(address => State)) public session;
    error SI__BadState();

    /// 2‑party handshake to establish state
    function open(address peer) external {
        session[msg.sender][peer] = State.Established;
    }
    function accept(address peer) external {
        session[msg.sender][peer] = State.Established;
    }

    /// only allow send if session established both ways
    function send(address to, bytes calldata data) external returns (bool) {
        if (session[msg.sender][to] != State.Established
         || session[to][msg.sender] != State.Established) {
            revert SI__BadState();
        }
        (bool ok, ) = to.call(data);
        return ok;
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) NO HANDSHAKE (FORWARD‑ONLY DATA)
///─────────────────────────────────────────────────────────────────────────────
contract HandshakeVuln {
    /// ❌ accepts data without any handshake
    function sendData(address to, bytes calldata data) external returns (bool) {
        (bool ok, ) = to.call(data);
        return ok;
    }
}

contract Attack_NoHandshake {
    HandshakeVuln public target;
    constructor(HandshakeVuln _t) { target = _t; }

    function phish(address victim, bytes calldata payload) external {
        // can send payload without any prior handshake
        target.sendData(victim, payload);
    }
}

contract HandshakeSafe {
    enum Phase { None, SynSent, Established }
    mapping(address => mapping(address => Phase)) public ph;

    error SI__BadState();

    /// client sends SYN
    function syn(address peer) external {
        ph[msg.sender][peer] = Phase.SynSent;
    }
    /// server responds with ACK
    function ack(address peer) external {
        require(ph[peer][msg.sender] == Phase.SynSent, "no SYN");
        ph[peer][msg.sender] = Phase.Established;
        ph[msg.sender][peer] = Phase.Established;
    }
    /// only after SYN+ACK may data flow
    function sendData(address to, bytes calldata data) external returns (bool) {
        if (ph[msg.sender][to] != Phase.Established) revert SI__BadState();
        (bool ok, ) = to.call(data);
        return ok;
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SESSION TIMEOUT (NO EXPIRY)
///─────────────────────────────────────────────────────────────────────────────
contract SessionTimeoutVuln {
    mapping(address => uint256) public lastActive;

    /// sessions never expire
    function openSession() external {
        lastActive[msg.sender] = block.timestamp;
    }
    function isActive(address user) external view returns (bool) {
        return lastActive[user] != 0;
    }
}

contract Attack_SessionTimeout {
    SessionTimeoutVuln public target;
    constructor(SessionTimeoutVuln _t) { target = _t; }

    function floodSessions(uint256 n) external {
        // caller opens session repeatedly; they never expire
        for (uint i = 0; i < n; i++) {
            target.openSession();
        }
    }
}

contract SessionTimeoutSafe {
    mapping(address => uint256) public lastActive;
    uint256 public constant TIMEOUT = 1 hours;
    error SI__SessionExpired();

    function openSession() external {
        lastActive[msg.sender] = block.timestamp;
    }
    function isActive(address user) external view returns (bool) {
        uint256 t = lastActive[user];
        if (t == 0 || block.timestamp > t + TIMEOUT) revert SI__SessionExpired();
        return true;
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SESSION TABLE OVERFLOW (NO LIMITS)
///─────────────────────────────────────────────────────────────────────────────
contract SessionTableVuln {
    address[] public sessions;

    /// ❌ anyone can open sessions for any user without limit
    function openSession(address user) external {
        sessions.push(user);
    }
}

contract Attack_SessionTableFlood {
    SessionTableVuln public target;
    constructor(SessionTableVuln _t) { target = _t; }

    function flood(address user, uint256 n) external {
        for (uint i = 0; i < n; i++) {
            target.openSession(user);
        }
    }
}

contract SessionTableSafe {
    address[] public sessions;
    mapping(address => uint256) public count;
    uint256 public constant MAX_PER_USER = 10;
    error SI__FloodDetected();

    function openSession(address user) external {
        if (count[user] >= MAX_PER_USER) revert SI__FloodDetected();
        sessions.push(user);
        count[user]++;
    }
}
