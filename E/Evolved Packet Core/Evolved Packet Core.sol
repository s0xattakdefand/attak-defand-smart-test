// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title EvolvedPacketCoreAttackDefense - Full Attack and Defense Simulation for Evolved Packet Core (EPC) Concepts in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure EPC Manager (Vulnerable to Session/Billing Drift and Unauthorized Hijacking)
contract InsecureEPCManager {
    struct Session {
        address owner;
        uint256 balance;
        uint256 expiry;
    }

    mapping(bytes32 => Session) public sessions;

    function startSession(bytes32 sessionId, uint256 expiry) external payable {
        sessions[sessionId] = Session({
            owner: msg.sender,
            balance: msg.value,
            expiry: expiry
        });
    }

    function spendSession(bytes32 sessionId, uint256 amount) external {
        require(sessions[sessionId].owner == msg.sender, "Not owner");
        require(block.timestamp <= sessions[sessionId].expiry, "Session expired");

        sessions[sessionId].balance -= amount;
    }

    function getSessionInfo(bytes32 sessionId) external view returns (Session memory) {
        return sessions[sessionId];
    }
}

/// @notice Secure EPC Manager (Hardened Session, Billing, and Authentication Control)
contract SecureEPCManager {
    address public owner;
    uint256 public sessionLifetime = 1 days;
    uint256 public minBalance = 0.01 ether;
    mapping(bytes32 => Session) public sessions;
    mapping(address => uint256) public nonces;
    mapping(bytes32 => bool) public usedSessionIds;

    struct Session {
        address owner;
        uint256 balance;
        uint256 createdAt;
        uint256 expiry;
    }

    event SessionStarted(bytes32 indexed sessionId, address indexed owner, uint256 expiry);
    event SessionSpent(bytes32 indexed sessionId, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function startSession(bytes32 sessionId, uint256 expiry, uint256 userNonce, uint8 v, bytes32 r, bytes32 s) external payable {
        require(!usedSessionIds[sessionId], "Session already exists");
        require(msg.value >= minBalance, "Insufficient starting balance");
        require(block.timestamp <= expiry, "Expiry already passed");
        require(userNonce == nonces[msg.sender], "Invalid nonce");

        bytes32 message = keccak256(abi.encodePacked(sessionId, expiry, userNonce, msg.sender, address(this), block.chainid));
        bytes32 ethSignedMessage = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", message));

        address recovered = ecrecover(ethSignedMessage, v, r, s);
        require(recovered == msg.sender, "Invalid signature");

        sessions[sessionId] = Session({
            owner: msg.sender,
            balance: msg.value,
            createdAt: block.timestamp,
            expiry: expiry
        });

        nonces[msg.sender]++;
        usedSessionIds[sessionId] = true;

        emit SessionStarted(sessionId, msg.sender, expiry);
    }

    function spendSession(bytes32 sessionId, uint256 amount) external {
        Session storage sess = sessions[sessionId];
        require(sess.owner == msg.sender, "Not session owner");
        require(block.timestamp <= sess.expiry, "Session expired");
        require(sess.balance >= amount, "Insufficient balance");

        sess.balance -= amount;

        emit SessionSpent(sessionId, amount);
    }

    function terminateExpiredSession(bytes32 sessionId) external {
        Session memory sess = sessions[sessionId];
        require(sess.owner != address(0), "Session does not exist");
        require(block.timestamp > sess.expiry, "Session still active");

        payable(sess.owner).transfer(sess.balance);
        delete sessions[sessionId];
    }

    function getSessionInfo(bytes32 sessionId) external view returns (Session memory) {
        return sessions[sessionId];
    }
}

/// @notice Attack contract simulating EPC session hijacks or replay attacks
contract EPCIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function hijackSession(bytes32 sessionId, uint256 amount) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("spendSession(bytes32,uint256)", sessionId, amount)
        );
    }
}
