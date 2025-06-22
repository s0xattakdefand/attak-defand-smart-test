// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title EvolvedNodeBAttackDefense - Full Attack and Defense Simulation for Evolved Node B (eNodeB) Adapted to Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Node Manager (Vulnerable to Session Hijacking and DoS)
contract InsecureNodeManager {
    mapping(bytes32 => address) public activeSessions;

    function startSession(bytes32 sessionId) external {
        activeSessions[sessionId] = msg.sender;
    }

    function handoffSession(bytes32 sessionId, address newAddress) external {
        require(activeSessions[sessionId] != address(0), "Session not found");
        activeSessions[sessionId] = newAddress;
    }

    function getSessionOwner(bytes32 sessionId) external view returns (address) {
        return activeSessions[sessionId];
    }
}

/// @notice Secure Node Manager (Full Authentication, Replay, and Spoofing Protection)
contract SecureNodeManager {
    address public owner;
    uint256 public sessionLifetime = 1 days;
    uint256 public maxSessionsPerAddress = 5;

    struct Session {
        address initiator;
        uint256 createdAt;
    }

    mapping(bytes32 => Session) public activeSessions;
    mapping(address => uint256) public sessionCount;
    mapping(address => bool) public trustedNodes;
    mapping(bytes32 => bool) public usedNonces;

    event SessionStarted(bytes32 indexed sessionId, address indexed initiator);
    event SessionHandedOver(bytes32 indexed sessionId, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function registerTrustedNode(address node) external onlyOwner {
        trustedNodes[node] = true;
    }

    function revokeTrustedNode(address node) external onlyOwner {
        trustedNodes[node] = false;
    }

    function startSession(bytes32 sessionId, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external {
        require(!usedNonces[keccak256(abi.encodePacked(nonce, msg.sender))], "Nonce already used");
        require(sessionCount[msg.sender] < maxSessionsPerAddress, "Session limit reached");

        bytes32 message = keccak256(abi.encodePacked(sessionId, msg.sender, nonce, address(this), block.chainid));
        address recovered = ecrecover(
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", message)),
            v, r, s
        );
        require(recovered == msg.sender, "Invalid session signature");

        activeSessions[sessionId] = Session({
            initiator: msg.sender,
            createdAt: block.timestamp
        });

        usedNonces[keccak256(abi.encodePacked(nonce, msg.sender))] = true;
        sessionCount[msg.sender]++;

        emit SessionStarted(sessionId, msg.sender);
    }

    function handoffSession(bytes32 sessionId, address newOwner) external {
        Session storage sess = activeSessions[sessionId];
        require(sess.initiator == msg.sender, "Not session owner");
        require(trustedNodes[newOwner], "New node not trusted");

        sess.initiator = newOwner;

        emit SessionHandedOver(sessionId, newOwner);
    }

    function cleanupExpiredSession(bytes32 sessionId) external {
        Session memory sess = activeSessions[sessionId];
        require(sess.initiator != address(0), "Session not found");
        require(block.timestamp > sess.createdAt + sessionLifetime, "Session still active");

        delete activeSessions[sessionId];
        sessionCount[sess.initiator]--;
    }

    function getSessionOwner(bytes32 sessionId) external view returns (address) {
        return activeSessions[sessionId].initiator;
    }
}

/// @notice Attack contract trying to hijack sessions or spoof sessions
contract NodeIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function fakeSession(bytes32 sessionId) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("startSession(bytes32)", sessionId)
        );
    }

    function hijackSession(bytes32 sessionId, address newVictim) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("handoffSession(bytes32,address)", sessionId, newVictim)
        );
    }
}
