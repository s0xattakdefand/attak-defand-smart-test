// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BiDirectionalSession {
    struct Session {
        string senderMsg;
        string receiverMsg;
        bool isActive;
    }

    mapping(address => mapping(address => Session)) public sessions;

    function initiate(address partner, string calldata msg_) external {
        sessions[msg.sender][partner] = Session(msg_, "", true);
    }

    function respond(address sender, string calldata reply) external {
        require(sessions[sender][msg.sender].isActive, "No active session");
        sessions[sender][msg.sender].receiverMsg = reply;
    }

    function readSession(address peer) external view returns (Session memory) {
        return sessions[msg.sender][peer];
    }
}
