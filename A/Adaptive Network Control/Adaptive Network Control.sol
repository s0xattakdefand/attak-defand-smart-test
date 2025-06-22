// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Adaptive Network Control Router (ANCR)
contract AdaptiveNetworkControl {
    address public admin;
    bool public systemLive = true;

    enum AccessLevel { NONE, RELAY, CONTROLLER, ADMIN }

    struct Peer {
        AccessLevel level;
        bool active;
    }

    mapping(address => Peer) public peers;

    event PeerUpdated(address peer, AccessLevel level, bool active);
    event RoutedAction(address peer, string command);
    event EmergencyTrigger(string reason);
    event SystemToggled(bool state);

    modifier onlyAdmin() {
        require(peers[msg.sender].level == AccessLevel.ADMIN, "Not admin");
        _;
    }

    modifier onlyActivePeer(AccessLevel minLevel) {
        Peer memory p = peers[msg.sender];
        require(systemLive, "System paused");
        require(p.active, "Peer inactive");
        require(uint(p.level) >= uint(minLevel), "Insufficient access");
        _;
    }

    constructor() {
        peers[msg.sender] = Peer(AccessLevel.ADMIN, true);
    }

    // Manage peers dynamically
    function setPeer(address peer, AccessLevel level, bool active) external onlyAdmin {
        peers[peer] = Peer(level, active);
        emit PeerUpdated(peer, level, active);
    }

    function route(string calldata command) external onlyActivePeer(AccessLevel.RELAY) {
        emit RoutedAction(msg.sender, command);
        // Optional: forward, log, trigger
    }

    function emergencyShutdown(string calldata reason) external onlyActivePeer(AccessLevel.CONTROLLER) {
        systemLive = false;
        emit EmergencyTrigger(reason);
    }

    function toggleSystem(bool live) external onlyAdmin {
        systemLive = live;
        emit SystemToggled(live);
    }

    function getPeerStatus(address peer) external view returns (AccessLevel level, bool active) {
        Peer memory p = peers[peer];
        return (p.level, p.active);
    }
}
