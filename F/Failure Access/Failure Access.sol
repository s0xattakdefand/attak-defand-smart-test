// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title FailureAccessAttackDefense - Full Attack and Defense Simulation for Failure Access Vulnerabilities in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Access Manager (Vulnerable to Access Control Failures)
contract InsecureAccessManager {
    address public admin;
    mapping(address => bool) public privileged;

    constructor() {
        admin = msg.sender;
        privileged[msg.sender] = true;
    }

    function grantPrivilege(address user) external {
        // BAD: Anyone can grant privilege without checks!
        privileged[user] = true;
    }

    function criticalAction() external view returns (string memory) {
        require(privileged[msg.sender], "Not privileged");
        return "Critical action executed!";
    }
}

/// @notice Secure Access Manager (Strict Role Protection and Fallback Rejection)
contract SecureAccessManager {
    address public admin;
    mapping(address => bool) public privileged;

    event PrivilegeGranted(address indexed user);
    event PrivilegeRevoked(address indexed user);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    modifier onlyPrivileged() {
        require(privileged[msg.sender], "Not privileged");
        _;
    }

    constructor() {
        admin = msg.sender;
        privileged[msg.sender] = true;
    }

    function grantPrivilege(address user) external onlyAdmin {
        require(user != address(0), "Invalid address");
        privileged[user] = true;
        emit PrivilegeGranted(user);
    }

    function revokePrivilege(address user) external onlyAdmin {
        privileged[user] = false;
        emit PrivilegeRevoked(user);
    }

    function criticalAction() external onlyPrivileged view returns (string memory) {
        return "Critical action executed safely!";
    }

    fallback() external payable {
        revert("Fallback not allowed");
    }
}

/// @notice Attack contract simulating failure access attempts
contract FailureAccessIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function hijackPrivilege(address myAddress) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("grantPrivilege(address)", myAddress)
        );
    }

    function tryCriticalAction() external returns (bool success, bytes memory data) {
        (success, data) = targetInsecure.call(
            abi.encodeWithSignature("criticalAction()")
        );
    }
}
