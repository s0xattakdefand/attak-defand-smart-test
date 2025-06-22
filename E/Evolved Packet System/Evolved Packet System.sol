// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title EvolvedPacketSystemAttackDefense - Full Attack and Defense Simulation for Evolved Packet System (EPS) Adapted to Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure EPS Manager (Vulnerable to Session Drift, Replay, and Billing Evasion)
contract InsecureEPSManager {
    struct Session {
        address user;
        uint256 resourcesRemaining;
        uint256 expiry;
    }

    mapping(bytes32 => Session) public sessions;

    function startSession(bytes32 sessionId, uint256 resources, uint256 expiry) external {
        sessions[sessionId] = Session({
            user: msg.sender,
            resourcesRemaining: resources,
            expiry: expiry
        });
    }

    function useResource(bytes32 sessionId, uint256 amount) external {
        require(sessions[sessionId].user == msg.sender, "Unauthorized");

        // BAD: No expiry check
        sessions[sessionId].resourcesRemaining -= amount;
    }
}

/// @notice Secure EPS Manager (Full Hardened Session, Routing, and Resource Control)
contract SecureEPSManager {
    address public owner;
    mapping(bytes32 => Session) public sessions;
    mapping(address => uint256) public nonces;
    mapping(bytes32 => bool) public usedSessions;

    struct Session {
        address user;
        uint256 resourcesRemaining;
        uint256 createdAt;
        uint256 expiry;
    }

    event SessionStarted(bytes32 indexed sessionId, address indexed user, uint256 resources, uint256 expiry);
    event ResourceUsed(bytes32 indexed sessionId, uint256 amountUsed);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function startSession(
        bytes32 sessionId,
        uint256 resources,
        uint256 expiry,
        uint256 userNonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(!usedSessions[sessionId], "Session already exists");
        require(expiry > block.timestamp, "Invalid expiry");
        require(resources > 0, "Invalid resources");
        require(userNonce == nonces[msg.sender], "Invalid nonce");

        bytes32 message = keccak256(abi.encodePacked(sessionId, resources, expiry, userNonce, msg.sender, address(this), block.chainid));
        bytes32 ethSigned = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", message));

        address recovered = ecrecover(ethSigned, v, r, s);
        require(recovered == msg.sender, "Invalid signature");

        sessions[sessionId] = Session({
            user: msg.sender,
            resourcesRemaining: resources,
            createdAt: block.timestamp,
            expiry: expiry
        });

        usedSessions[sessionId] = true;
        nonces[msg.sender]++;

        emit SessionStarted(sessionId, msg.sender, resources, expiry);
    }

    function useResource(bytes32 sessionId, uint256 amount) external {
        Session storage sess = sessions[sessionId];

        require(sess.user == msg.sender, "Unauthorized user");
        require(block.timestamp <= sess.expiry, "Session expired");
        require(sess.resourcesRemaining >= amount, "Not enough resources");

        sess.resourcesRemaining -= amount;

        emit ResourceUsed(sessionId, amount);
    }

    function expireSession(bytes32 sessionId) external {
        Session memory sess = sessions[sessionId];
        require(sess.user != address(0), "Session not found");
        require(block.timestamp > sess.expiry, "Session still active");

        delete sessions[sessionId];
    }

    function getSession(bytes32 sessionId) external view returns (Session memory) {
        return sessions[sessionId];
    }
}

/// @notice Attack contract trying to abuse insecure EPS sessions
contract EPSIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function abuseResource(bytes32 sessionId, uint256 amount) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("useResource(bytes32,uint256)", sessionId, amount)
        );
    }
}
