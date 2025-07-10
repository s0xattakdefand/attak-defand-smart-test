// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * DATAGRAM CONGESTION CONTROL PROTOCOL (DCCP) DEMO
 * 
 * SECTION 1 — VulnerableDatagramSender
 *   • Sends unlimited datagrams with no congestion control.
 *
 * SECTION 2 — DCCPSender
 *   • Implements a basic DCCP-like sliding window:
 *     – Slow start (cwnd grows exponentially until ssthresh)
 *     – Congestion avoidance (linear growth after ssthresh)
 *     – Loss reaction (ssthresh = cwnd/2; cwnd reset to 1)
 *     – In-flight tracking (cannot send when inFlight ≥ cwnd)
 */

/// -------------------------------------------------------------------------
/// SECTION 1 — VulnerableDatagramSender
/// -------------------------------------------------------------------------
contract VulnerableDatagramSender {
    event DatagramSent(address indexed from, address indexed to, uint256 indexed id, bytes payload);
    uint256 public nextDatagramId;

    /// @notice Send a datagram with no congestion control
    function sendDatagram(address to, bytes calldata payload) external {
        uint256 id = nextDatagramId++;
        emit DatagramSent(msg.sender, to, id, payload);
    }
}

/// -------------------------------------------------------------------------
/// SECTION 2 — DCCPSender
/// -------------------------------------------------------------------------
contract DCCPSender {
    event DatagramSent(address indexed from, address indexed to, uint256 indexed id, bytes payload, uint256 cwnd);
    event AckReceived(address indexed to, uint256 indexed id, uint256 cwnd, uint256 ssthresh);
    event LossDetected(address indexed to, uint256 indexed id, uint256 cwnd, uint256 ssthresh);

    struct Flow {
        uint256 cwnd;        // congestion window (max in-flight)
        uint256 ssthresh;    // slow-start threshold
        uint256 inFlight;    // currently unacked datagrams
    }

    mapping(address => Flow) public flows;
    uint256 public nextDatagramId;

    uint256 public constant INITIAL_CWND = 1;
    uint256 public constant INITIAL_SSTH = 16;

    /// @dev Initialize flow state if first use
    function _initFlow(address to) internal {
        Flow storage f = flows[to];
        if (f.cwnd == 0) {
            f.cwnd = INITIAL_CWND;
            f.ssthresh = INITIAL_SSTH;
            f.inFlight = 0;
        }
    }

    /// @notice Send a datagram, constrained by cwnd
    function sendDatagram(address to, bytes calldata payload) external {
        _initFlow(to);
        Flow storage f = flows[to];
        require(f.inFlight < f.cwnd, "DCCP: window full");
        uint256 id = nextDatagramId++;
        f.inFlight += 1;
        emit DatagramSent(msg.sender, to, id, payload, f.cwnd);
    }

    /// @notice Receiver calls to acknowledge a datagram
    function receiveAck(address to, uint256 datagramId) external {
        Flow storage f = flows[to];
        require(f.inFlight > 0, "DCCP: no in-flight");
        f.inFlight -= 1;

        // Slow start: exponential growth until cwnd >= ssthresh
        if (f.cwnd < f.ssthresh) {
            f.cwnd += 1;
        } else {
            // Congestion avoidance: linear growth
            f.cwnd += 1;
        }

        emit AckReceived(to, datagramId, f.cwnd, f.ssthresh);
    }

    /// @notice Signal a loss event for a given datagram
    function signalLoss(address to, uint256 datagramId) external {
        Flow storage f = flows[to];
        require(f.inFlight > 0, "DCCP: no in-flight");
        // On loss: half ssthresh, reset cwnd to 1
        uint256 newSsth = f.cwnd / 2;
        f.ssthresh = newSsth > 1 ? newSsth : 1;
        f.cwnd = INITIAL_CWND;
        f.inFlight -= 1;
        emit LossDetected(to, datagramId, f.cwnd, f.ssthresh);
    }

    /// @notice Query current flow state for a destination
    function getFlow(address to) external view returns (uint256 cwnd, uint256 ssthresh, uint256 inFlight) {
        Flow storage f = flows[to];
        return (f.cwnd, f.ssthresh, f.inFlight);
    }
}
