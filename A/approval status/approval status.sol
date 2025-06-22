// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract ApprovalStatusManager {
    address public admin;

    mapping(address => bool) public isApproved;
    mapping(address => uint256) public approvedSince;

    event Approved(address indexed user);
    event Revoked(address indexed user);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier onlyApproved() {
        require(isApproved[msg.sender], "Not approved");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function approve(address user) external onlyAdmin {
        require(!isApproved[user], "Already approved");
        isApproved[user] = true;
        approvedSince[user] = block.timestamp;
        emit Approved(user);
    }

    function revoke(address user) external onlyAdmin {
        require(isApproved[user], "Not approved");
        isApproved[user] = false;
        emit Revoked(user);
    }

    function checkApproval(address user) external view returns (bool approved, uint256 since) {
        return (isApproved[user], approvedSince[user]);
    }

    // Example of an action that requires approval
    function performApprovedAction() external onlyApproved returns (string memory) {
        return "Action executed.";
    }
}
