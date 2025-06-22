// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Ad Hoc Peer Network Simulation
contract AdHocNetwork {
    address public admin;
    mapping(address => bool) public peers;
    mapping(bytes32 => bool) public executedSessions;

    event PeerJoined(address indexed peer);
    event PeerLeft(address indexed peer);
    event SessionExecuted(address indexed initiator, bytes32 sessionId);

    modifier onlyPeer() {
        require(peers[msg.sender], "Not a peer");
        _;
    }

    constructor() {
        admin = msg.sender;
        peers[msg.sender] = true;
    }

    // Self-join (could extend with signature or bonding)
    function joinNetwork() external {
        require(!peers[msg.sender], "Already joined");
        peers[msg.sender] = true;
        emit PeerJoined(msg.sender);
    }

    function leaveNetwork() external {
        require(peers[msg.sender], "Not in network");
        delete peers[msg.sender];
        emit PeerLeft(msg.sender);
    }

    function executeSession(bytes32 sessionId) external onlyPeer {
        require(!executedSessions[sessionId], "Session already used");
        executedSessions[sessionId] = true;
        emit SessionExecuted(msg.sender, sessionId);
    }

    function isPeer(address user) external view returns (bool) {
        return peers[user];
    }

    function hasExecuted(bytes32 sessionId) external view returns (bool) {
        return executedSessions[sessionId];
    }
}
