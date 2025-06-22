// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AdequateSecurityLayer {
    address public admin;
    mapping(address => bool) public authorized;
    mapping(address => uint256) public lastCallBlock;
    bool public emergencyPaused;

    event AccessGranted(address user);
    event AccessDenied(address user, string reason);
    event Paused();
    event Unpaused();

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier onlyAuthorized() {
        if (!authorized[msg.sender]) {
            emit AccessDenied(msg.sender, "Not authorized");
            revert("Access denied");
        }
        _;
    }

    modifier notPaused() {
        require(!emergencyPaused, "System paused");
        _;
    }

    modifier rateLimited() {
        require(block.number > lastCallBlock[msg.sender], "Too frequent");
        lastCallBlock[msg.sender] = block.number;
        _;
    }

    constructor() {
        admin = msg.sender;
        authorized[msg.sender] = true;
    }

    function togglePause(bool state) external onlyAdmin {
        emergencyPaused = state;
        if (state) emit Paused(); else emit Unpaused();
    }

    function authorize(address user) external onlyAdmin {
        authorized[user] = true;
        emit AccessGranted(user);
    }

    function secureAction() external onlyAuthorized notPaused rateLimited {
        // Secure logic here
    }
}
