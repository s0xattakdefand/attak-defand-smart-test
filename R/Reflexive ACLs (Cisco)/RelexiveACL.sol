// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract ReflexiveACL {
    struct Session {
        bool allowed;
        uint256 expiresAt;
    }

    mapping(address => Session) public sessions;

    event OutboundInitiated(address indexed user, uint256 expiresAt);
    event InboundAllowed(address indexed user);
    event InboundRevoked(address indexed user);

    modifier reflexiveAccess() {
        require(sessions[msg.sender].allowed, "ReflexiveACL: no session");
        require(block.timestamp <= sessions[msg.sender].expiresAt, "Session expired");
        _;
        delete sessions[msg.sender];
        emit InboundRevoked(msg.sender);
    }

    /// Simulate outbound session (e.g., MetaTx relay, verified vote)
    function initiateSession(address user, uint256 duration) external {
        sessions[user] = Session(true, block.timestamp + duration);
        emit OutboundInitiated(user, block.timestamp + duration);
    }

    /// Reflexive access method — only allowed temporarily
    function sensitiveOperation() external reflexiveAccess {
        emit InboundAllowed(msg.sender);
        // Your sensitive logic here
    }
}
