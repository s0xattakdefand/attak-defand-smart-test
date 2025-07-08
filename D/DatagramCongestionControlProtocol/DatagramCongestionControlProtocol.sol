// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * DATAGRAM CONGESTION CONTROL PROTOCOL DEMO
 * Illustrates:
 *   1) VulnerableDatagramSender  — naive sender allows unlimited sends (no congestion control)
 *   2) SimpleDCCPSender          — implements a basic DCCP-like sliding window with slow start,
 *                                  congestion avoidance, and loss reaction.
 */

/*----------------------------------------------------------------------------
   SECTION 1 — VulnerableDatagramSender (⚠️ no flow control)
----------------------------------------------------------------------------*/
contract VulnerableDatagramSender {
    event DatagramSent(address indexed to, uint256 indexed datagramId, bytes payload);

    uint256 public nextDatagramId;

    /// Send any number of datagrams without regard for congestion
    function sendDatagram(address to, bytes calldata payload) external {
        uint256 id = nextDatagramId++;
        emit DatagramSent(to, id, payload);
    }
}

/*----------------------------------------------------------------------------
   SECTION 2 — SimpleDCCPSender (✅ basic congestion control)
----------------------------------------------------------------------------*/
contract SimpleDCCPSender {
    event DatagramSent(address indexed to, uint256 indexed datagramId, bytes payload, uint256 cwnd);
    event AckReceived(address indexed to, uint256 indexed datagramId, uint256 cwnd, uint256 ssthresh);
    event LossDetected(address indexed to, uint256 indexed datagramId, uint256 cwnd, uint256 ssthresh);

    struct Flow {
        uint256 cwnd;        // congestion window (max in-flight)
        uint256 ssthresh;    // slow-start threshold
        uint256 inFlight;    // currently unacked datagrams
    }

    mapping(address => Flow) public flows;
    uint256 public nextDatagramId;

    uint256 public constant INITIAL_CWND = 1;
    uint256 public constant INITIAL_SSTH = 16;

    constructor() {
        // no-op
    }

    /// Initialize flow state if first use
    function _initFlow(address to) internal {
        Flow storage f = flows[to];
        if (f.cwnd == 0) {
            f.cwnd = INITIAL_CWND;
            f.ssthresh = INITIAL_SSTH;
            f.inFlight = 0;
        }
    }

    /// Send a datagram, constrained by cwnd
    function sendDatagram(address to, bytes calldata payload) external {
        _initFlow(to);
        Flow storage f = flows[to];
        require(f.inFlight < f.cwnd, "Flow: window full");
        uint256 id = nextDatagramId++;
        f.inFlight += 1;
        emit DatagramSent(to, id, payload, f.cwnd);
    }

    /// Receiver calls on ack; datagramId must be one previously sent
    function receiveAck(address to, uint256 datagramId) external {
        Flow storage f = flows[to];
        require(f.inFlight > 0, "Flow: no in-flight");
        f.inFlight -= 1;

        // Slow start
        if (f.cwnd < f.ssthresh) {
            f.cwnd += 1;
        } else {
            // Congestion avoidance: linear growth
            f.cwnd += 1 / f.cwnd > 0 ? 1 : 0;
        }

        emit AckReceived(to, datagramId, f.cwnd, f.ssthresh);
    }

    /// Simulate loss event for a given datagram
    function signalLoss(address to, uint256 datagramId) external {
        Flow storage f = flows[to];
        require(f.inFlight > 0, "Flow: no in-flight");
        // On loss, enter congestion avoidance
        f.ssthresh = f.cwnd / 2 > 1 ? f.cwnd / 2 : 1;
        f.cwnd = INITIAL_CWND;
        f.inFlight -= 1; // assume datagram wiped
        emit LossDetected(to, datagramId, f.cwnd, f.ssthresh);
    }

    /// Query current flow control state
    function getFlow(address to) external view returns (uint256 cwnd, uint256 ssthresh, uint256 inFlight) {
        Flow storage f = flows[to];
        return (f.cwnd, f.ssthresh, f.inFlight);
    }
}
