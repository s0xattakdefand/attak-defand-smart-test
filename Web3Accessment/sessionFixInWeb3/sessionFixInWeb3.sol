// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title SessionFixationAttackDefense - Full Attack and Defense Simulation for Session Fixation Testing
/// @author ChatGPT

/// @notice Secure smart contract protecting against Session Fixation attacks
contract SecureSessionFixation {
    address public owner;

    struct Session {
        address user;
        uint256 createdAt;
        uint256 expiresAt;
        bool active;
    }

    mapping(bytes32 => Session) public sessions;
    uint256 public sessionCounter;

    event SessionCreated(bytes32 indexed sessionId, address indexed user, uint256 expiresAt);
    event SessionTerminated(bytes32 indexed sessionId);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function createSession(uint256 _durationSeconds) external returns (bytes32 sessionId) {
        require(_durationSeconds > 0, "Invalid duration");

        sessionCounter++;
        sessionId = keccak256(
            abi.encodePacked(msg.sender, block.timestamp, block.number, sessionCounter)
        );

        sessions[sessionId] = Session({
            user: msg.sender,
            createdAt: block.timestamp,
            expiresAt: block.timestamp + _durationSeconds,
            active: true
        });

        emit SessionCreated(sessionId, msg.sender, block.timestamp + _durationSeconds);
    }

    function validateSession(bytes32 _sessionId) external view returns (bool) {
        Session memory s = sessions[_sessionId];
        return (
            s.active &&
            s.expiresAt > block.timestamp &&
            s.user == msg.sender
        );
    }

    function terminateSession(bytes32 _sessionId) external {
        require(sessions[_sessionId].user == msg.sender, "Not session owner");
        sessions[_sessionId].active = false;
        emit SessionTerminated(_sessionId);
    }
}

/// @notice Attack contract trying to predict/fixate session
contract SessionFixationIntruder {
    address public target;

    constructor(address _target) {
        target = _target;
    }

    function tryFixedSession(bytes32 guessedSessionId) external view returns (bool success) {
        (bool callSuccess, bytes memory result) = target.staticcall(
            abi.encodeWithSignature("validateSession(bytes32)", guessedSessionId)
        );
        require(callSuccess, "Call failed");
        success = abi.decode(result, (bool));
    }
}
