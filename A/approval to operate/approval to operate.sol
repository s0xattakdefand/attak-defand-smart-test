// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract ApprovalToOperateManager {
    address public admin;

    // owner → operator → approved
    mapping(address => mapping(address => bool)) public approvedOperators;
    mapping(address => mapping(address => uint256)) public approvalTimestamps;

    event OperatorApproved(address indexed owner, address indexed operator);
    event OperatorRevoked(address indexed owner, address indexed operator);
    event OperationPerformed(address indexed operator, address indexed owner);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    // --- ATO Grant ---
    function approveOperator(address operator) external {
        require(operator != address(0), "Invalid operator");
        approvedOperators[msg.sender][operator] = true;
        approvalTimestamps[msg.sender][operator] = block.timestamp;
        emit OperatorApproved(msg.sender, operator);
    }

    // --- ATO Revoke ---
    function revokeOperator(address operator) external {
        require(approvedOperators[msg.sender][operator], "Not approved");
        approvedOperators[msg.sender][operator] = false;
        emit OperatorRevoked(msg.sender, operator);
    }

    // --- ATO-Enforced Logic ---
    function performSensitiveOperation(address owner) external {
        require(approvedOperators[owner][msg.sender], "Not approved to operate");
        emit OperationPerformed(msg.sender, owner);
        // execute sensitive logic here...
    }

    function isOperatorApproved(address owner, address operator) external view returns (bool) {
        return approvedOperators[owner][operator];
    }

    function getApprovalTime(address owner, address operator) external view returns (uint256) {
        return approvalTimestamps[owner][operator];
    }
}
