// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title SessionManagementAttackDefense - Full Simulation for Session Management Attacks and Defenses
/// @author ChatGPT

/// @notice Secure smart contract handling session management safely
contract SecureSessionManager {
    address public owner;

    struct Session {
        address user;
        uint256 expiresAt;
        bool active;
    }

    mapping(bytes32 => Session) public sessions;

    event SessionCreated(bytes32 indexed sessionId, address indexed user, uint256 expiresAt);
    event SessionTerminated(bytes32 indexed sessionId);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function createSession(address _user, uint256 _durationSeconds) external onlyOwner returns (bytes32 sessionId) {
        require(_user != address(0), "Invalid user");
        require(_durationSeconds > 0, "Invalid duration");

        sessionId = keccak256(abi.encodePacked(_user, block.timestamp, block.number));
        sessions[sessionId] = Session({
            user: _user,
            expiresAt: block.timestamp + _durationSeconds,
            active: true
        });

        emit SessionCreated(sessionId, _user, block.timestamp + _durationSeconds);
    }

    function validateSession(bytes32 _sessionId) external view returns (bool) {
        Session memory s = sessions[_sessionId];
        return s.active && s.expiresAt > block.timestamp && s.user == msg.sender;
    }

    function terminateSession(bytes32 _sessionId) external {
        require(sessions[_sessionId].user == msg.sender, "Not session owner");
        sessions[_sessionId].active = false;
        emit SessionTerminated(_sessionId);
    }
}

/// @notice Attack contract trying to hijack or misuse session
contract SessionIntruder {
    address public target;

    constructor(address _target) {
        target = _target;
    }

    function tryValidateSession(bytes32 fakeSessionId) external view returns (bool isValid) {
        (bool success, bytes memory result) = target.staticcall(
            abi.encodeWithSignature("validateSession(bytes32)", fakeSessionId)
        );

        require(success, "Validation call failed");
        isValid = abi.decode(result, (bool));
    }
}
