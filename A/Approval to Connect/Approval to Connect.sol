// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract ConnectApprovalManager {
    address public admin;

    // user => approved connection => status
    mapping(address => mapping(address => bool)) public isConnectionApproved;
    mapping(address => uint256) public lastConnectTimestamp;

    event ConnectRequested(address indexed from, address indexed to);
    event ConnectionApproved(address indexed from, address indexed to);
    event ConnectionRevoked(address indexed from, address indexed to);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    // Request and auto-emit request event (does not auto-approve)
    function requestConnect(address to) external {
        emit ConnectRequested(msg.sender, to);
        lastConnectTimestamp[msg.sender] = block.timestamp;
    }

    function approveConnection(address from, address to) external onlyAdmin {
        isConnectionApproved[from][to] = true;
        emit ConnectionApproved(from, to);
    }

    function revokeConnection(address from, address to) external onlyAdmin {
        isConnectionApproved[from][to] = false;
        emit ConnectionRevoked(from, to);
    }

    function checkApproval(address from, address to) external view returns (bool) {
        return isConnectionApproved[from][to];
    }

    // Example: Protected cross-connection logic
    function connectWith(address to) external {
        require(isConnectionApproved[msg.sender][to], "Connect: not approved");
        // logic here...
    }
}
