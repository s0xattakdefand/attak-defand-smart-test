// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IModuleA {
    function performActionA(address user, uint256 amount) external;
}

interface IModuleB {
    function performActionB(address user, bytes calldata data) external;
}

contract ComplexSystemCoordinator {
    address public admin;
    address public moduleA;
    address public moduleB;

    mapping(address => bool) public isApprovedUser;

    event ActionExecuted(address indexed user, string module, uint256 timestamp);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier onlyApproved() {
        require(isApprovedUser[msg.sender], "Not approved");
        _;
    }

    constructor(address _moduleA, address _moduleB) {
        admin = msg.sender;
        moduleA = _moduleA;
        moduleB = _moduleB;
    }

    function approveUser(address user) external onlyAdmin {
        isApprovedUser[user] = true;
    }

    function revokeUser(address user) external onlyAdmin {
        isApprovedUser[user] = false;
    }

    function executeWorkflow(address user, uint256 amount, bytes calldata data) external onlyApproved {
        IModuleA(moduleA).performActionA(user, amount);
        emit ActionExecuted(user, "ModuleA", block.timestamp);

        IModuleB(moduleB).performActionB(user, data);
        emit ActionExecuted(user, "ModuleB", block.timestamp);
    }
}
