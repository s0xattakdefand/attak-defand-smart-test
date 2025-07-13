// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * DEAD PEER DETECTION (DPD) SMART CONTRACT
 * 
 * Implements a basic Dead Peer Detection mechanism:
 *  - Admin registers/deregisters peers.
 *  - Peers call `heartbeat()` to signal they are alive.
 *  - Anyone can call `checkDeadPeers()` to detect peers whose last
 *    heartbeat is older than the configured timeout.
 *  - Emits events on registration, heartbeat, death detection, and revival.
 */

contract DeadPeerDetection {
    address public admin;
    uint256 public heartbeatTimeout;   // in seconds

    struct Peer {
        uint256 lastHeartbeat;
        bool    exists;
        bool    isDead;
    }

    mapping(address => Peer) public peers;
    address[] public peerList;
    mapping(address => uint256) private peerIndex;

    event AdminTransferred(address indexed oldAdmin, address indexed newAdmin);
    event TimeoutUpdated(uint256 oldTimeout, uint256 newTimeout);

    event PeerRegistered(address indexed peer);
    event PeerDeregistered(address indexed peer);

    event HeartbeatReceived(address indexed peer, uint256 timestamp);
    event PeerDead(address indexed peer, uint256 atTimestamp);
    event PeerRevived(address indexed peer, uint256 atTimestamp);

    modifier onlyAdmin() {
        require(msg.sender == admin, "DPD: not admin");
        _;
    }

    modifier onlyPeer() {
        require(peers[msg.sender].exists, "DPD: not a registered peer");
        _;
    }

    constructor(uint256 _heartbeatTimeout) {
        require(_heartbeatTimeout > 0, "DPD: timeout must be > 0");
        admin = msg.sender;
        heartbeatTimeout = _heartbeatTimeout;
        emit AdminTransferred(address(0), admin);
        emit TimeoutUpdated(0, _heartbeatTimeout);
    }

    /// @notice Transfer admin role
    function transferAdmin(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "DPD: zero address");
        emit AdminTransferred(admin, newAdmin);
        admin = newAdmin;
    }

    /// @notice Update the heartbeat timeout
    function updateHeartbeatTimeout(uint256 newTimeout) external onlyAdmin {
        require(newTimeout > 0, "DPD: timeout must be > 0");
        emit TimeoutUpdated(heartbeatTimeout, newTimeout);
        heartbeatTimeout = newTimeout;
    }

    /// @notice Register a new peer
    function registerPeer(address peer) external onlyAdmin {
        require(peer != address(0), "DPD: zero address");
        Peer storage p = peers[peer];
        require(!p.exists, "DPD: already registered");
        p.exists = true;
        p.isDead = false;
        p.lastHeartbeat = block.timestamp;

        peerIndex[peer] = peerList.length;
        peerList.push(peer);

        emit PeerRegistered(peer);
    }

    /// @notice Deregister an existing peer
    function deregisterPeer(address peer) external onlyAdmin {
        Peer storage p = peers[peer];
        require(p.exists, "DPD: not registered");

        // Remove from peerList array
        uint256 idx = peerIndex[peer];
        address lastPeer = peerList[peerList.length - 1];
        peerList[idx] = lastPeer;
        peerIndex[lastPeer] = idx;
        peerList.pop();

        delete peerIndex[peer];
        delete peers[peer];

        emit PeerDeregistered(peer);
    }

    /// @notice Called by a peer to signal it is alive
    function heartbeat() external onlyPeer {
        Peer storage p = peers[msg.sender];
        uint256 nowTs = block.timestamp;

        // If previously detected dead, mark revived
        if (p.isDead) {
            p.isDead = false;
            emit PeerRevived(msg.sender, nowTs);
        }

        p.lastHeartbeat = nowTs;
        emit HeartbeatReceived(msg.sender, nowTs);
    }

    /// @notice Check all registered peers and emit PeerDead for those timed out
    function checkDeadPeers() external {
        uint256 nowTs = block.timestamp;
        for (uint256 i = 0; i < peerList.length; i++) {
            address peer = peerList[i];
            Peer storage p = peers[peer];
            if (!p.isDead && nowTs > p.lastHeartbeat + heartbeatTimeout) {
                p.isDead = true;
                emit PeerDead(peer, nowTs);
            }
        }
    }

    /// @notice Get the number of registered peers
    function peerCount() external view returns (uint256) {
        return peerList.length;
    }

    /// @notice Retrieve peer by index
    function peerAt(uint256 index) external view returns (address) {
        require(index < peerList.length, "DPD: index out of bounds");
        return peerList[index];
    }
}
