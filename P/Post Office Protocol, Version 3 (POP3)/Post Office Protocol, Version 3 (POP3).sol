// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ========== POP3 BASIC INBOX ========== */
contract POP3Inbox {
    struct Message {
        address from;
        string content;
        bool read;
        bool deleted;
    }

    mapping(address => Message[]) public inbox;

    event MessageSent(address indexed to, string content);
    event MessageRead(address indexed user, uint256 index);
    event MessageDeleted(address indexed user, uint256 index);

    function sendMessage(address to, string calldata content) external {
        inbox[to].push(Message(msg.sender, content, false, false));
        emit MessageSent(to, content);
    }

    function readMessage(uint256 index) external view returns (string memory) {
        require(index < inbox[msg.sender].length, "Out of bounds");
        Message memory msg_ = inbox[msg.sender][index];
        require(!msg_.deleted, "Deleted");
        return msg_.content;
    }

    function markRead(uint256 index) external {
        require(index < inbox[msg.sender].length, "Out of bounds");
        inbox[msg.sender][index].read = true;
        emit MessageRead(msg.sender, index);
    }

    function deleteMessage(uint256 index) external {
        require(index < inbox[msg.sender].length, "Out of bounds");
        inbox[msg.sender][index].deleted = true;
        emit MessageDeleted(msg.sender, index);
    }

    function messageCount(address user) external view returns (uint256) {
        return inbox[user].length;
    }
}

/* ========== ADVANCED DEFENSE ========== */

// 🛡 Token-Gated POP3
interface IPermitToken {
    function isApproved(address user) external view returns (bool);
}

contract AuthPOP3 {
    IPermitToken public token;

    constructor(address tokenAddr) {
        token = IPermitToken(tokenAddr);
    }

    mapping(address => string[]) private secureInbox;

    function secureSend(address to, string calldata content) external {
        secureInbox[to].push(content);
    }

    function secureRead(uint256 i) external view returns (string memory) {
        require(token.isApproved(msg.sender), "No access");
        return secureInbox[msg.sender][i];
    }
}

// 🛡 zkPOP3 (Simulated)
contract zkInbox {
    mapping(bytes32 => string[]) public zkInboxData;

    function sendToZK(bytes32 zkID, string calldata msg_) external {
        zkInboxData[zkID].push(msg_);
    }

    function readZK(bytes32 zkID, uint256 i) external view returns (string memory) {
        return zkInboxData[zkID][i];
    }
}
