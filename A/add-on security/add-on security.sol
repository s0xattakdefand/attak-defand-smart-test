// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Add-On Security Layer: Plug & Play Guard
contract AddOnSecurity {
    address public admin;
    mapping(address => uint256) public callRate;
    mapping(address => bool) public blocked;
    uint256 public lastBlock;

    event AccessGranted(address caller);
    event AccessBlocked(address caller, string reason);
    event AdminUpdated(address newAdmin);

    modifier secured(string memory action) {
        require(!blocked[msg.sender], "Blocked address");
        require(gasleft() > 40000, "Low gas anomaly");

        // Simple block throttle
        require(block.number != lastBlock, "Rapid call blocked");
        lastBlock = block.number;

        callRate[msg.sender]++;
        if (callRate[msg.sender] > 10) {
            blocked[msg.sender] = true;
            emit AccessBlocked(msg.sender, "Rate limit");
            revert("Access denied");
        }

        emit AccessGranted(msg.sender);
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function unblock(address user) external {
        require(msg.sender == admin, "Not admin");
        blocked[user] = false;
        callRate[user] = 0;
    }

    function getStatus(address user) external view returns (bool, uint256) {
        return (blocked[user], callRate[user]);
    }

    function updateAdmin(address newAdmin) external {
        require(msg.sender == admin, "Not admin");
        admin = newAdmin;
        emit AdminUpdated(newAdmin);
    }
}
