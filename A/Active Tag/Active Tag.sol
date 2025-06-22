// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ActiveStateManager {
    address public admin;
    bool public systemActive = true;
    mapping(address => bool) public userActive;

    event SystemToggled(bool state);
    event UserToggled(address indexed user, bool state);

    modifier onlyActive() {
        require(systemActive, "System is paused");
        _;
    }

    modifier onlyActiveUser() {
        require(userActive[msg.sender], "User not active");
        _;
    }

    constructor() {
        admin = msg.sender;
        userActive[admin] = true;
    }

    function toggleSystem(bool status) external {
        require(msg.sender == admin, "Not admin");
        systemActive = status;
        emit SystemToggled(status);
    }

    function setUserActive(address user, bool status) external {
        require(msg.sender == admin, "Not admin");
        userActive[user] = status;
        emit UserToggled(user, status);
    }

    function performAction() external onlyActive onlyActiveUser {
        // logic
    }
}
