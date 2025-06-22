// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title DeadPeerDetectionAttackDefense - Full Attack and Defense Simulation for Dead Peer Detection Systems in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Secure Peer Detection Contract with Signed Heartbeat Mechanism
contract SecurePeerRegistry {
    address public owner;
    uint256 public heartbeatExpiry = 50; // Blocks
    uint256 public heartbeatCooldown = 10; // Blocks

    struct PeerInfo {
        uint256 lastHeartbeatBlock;
        bool registered;
    }

    mapping(address => PeerInfo) public peers;

    event PeerRegistered(address indexed peer);
    event HeartbeatReceived(address indexed peer, uint256 blockNumber);
    event PeerMarkedDead(address indexed peer);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function registerPeer(address peer) external onlyOwner {
        require(peer != address(0), "Invalid peer address");
        require(!peers[peer].registered, "Already registered");

        peers[peer] = PeerInfo({
            lastHeartbeatBlock: block.number,
            registered: true
        });

        emit PeerRegistered(peer);
    }

    function heartbeat(uint8 v, bytes32 r, bytes32 s) external {
        PeerInfo storage peer = peers[msg.sender];
        require(peer.registered, "Peer not registered");
        require(block.number > peer.lastHeartbeatBlock + heartbeatCooldown, "Heartbeat too soon");

        bytes32 message = keccak256(abi.encodePacked(msg.sender, address(this), block.number));
        bytes32 ethSignedMessage = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", message));

        address recovered = ecrecover(ethSignedMessage, v, r, s);
        require(recovered == msg.sender, "Invalid heartbeat signature");

        peer.lastHeartbeatBlock = block.number;

        emit HeartbeatReceived(msg.sender, block.number);
    }

    function checkPeerAlive(address peer) external view returns (bool isAlive) {
        PeerInfo memory p = peers[peer];
        if (!p.registered) return false;
        if (block.number > p.lastHeartbeatBlock + heartbeatExpiry) return false;
        return true;
    }

    function markPeerDead(address peer) external onlyOwner {
        PeerInfo storage p = peers[peer];
        require(p.registered, "Peer not registered");
        require(block.number > p.lastHeartbeatBlock + heartbeatExpiry, "Peer still alive");

        delete peers[peer];
        emit PeerMarkedDead(peer);
    }
}

/// @notice Attack contract trying to spoof alive heartbeats
contract DeadPeerIntruder {
    address public targetRegistry;

    constructor(address _targetRegistry) {
        targetRegistry = _targetRegistry;
    }

    function fakeHeartbeat(uint256 fakeBlockNumber) external returns (bool success) {
        (success, ) = targetRegistry.call(
            abi.encodeWithSignature("heartbeat(uint8,bytes32,bytes32)", 27, bytes32(0), bytes32(0))
        );
    }
}
