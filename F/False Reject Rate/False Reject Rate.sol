// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title FalseRejectRateAttackDefense - Full Attack and Defense Simulation for False Reject Rate Vulnerabilities in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Access Manager (High False Reject Rate due to rigid checks)
contract InsecureFalseRejectRateManager {
    address public admin;
    mapping(address => bool) public authorized;
    bytes32 public domainSeparator;
    uint256 public expireLimit = 10; // Very tight window — BAD

    constructor() {
        admin = msg.sender;
        domainSeparator = keccak256(abi.encodePacked(block.chainid, address(this)));
        authorized[msg.sender] = true;
    }

    function verifyAccess(uint256 timestamp, uint8 v, bytes32 r, bytes32 s) public view returns (bool) {
        require(block.timestamp <= timestamp + expireLimit, "Timestamp too old");

        bytes32 message = keccak256(abi.encodePacked(msg.sender, timestamp, domainSeparator));
        bytes32 ethSigned = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", message));

        address signer = ecrecover(ethSigned, v, r, s);
        return authorized[signer];
    }

    function criticalAction(uint256 timestamp, uint8 v, bytes32 r, bytes32 s) external view returns (string memory) {
        require(verifyAccess(timestamp, v, r, s), "Rejected");
        return "Insecure action executed.";
    }
}

/// @notice Secure Access Manager (Dynamic Threshold to Control False Reject Rate)
contract SecureFalseRejectRateManager {
    address public admin;
    mapping(address => bool) public authorized;
    bytes32 public domainSeparator;
    uint256 public expireLimit = 60; // Reasonable flexible window (60s)

    event AccessAttempt(address indexed user, bool success, string reason);

    constructor() {
        admin = msg.sender;
        domainSeparator = keccak256(abi.encodePacked(block.chainid, address(this)));
        authorized[msg.sender] = true;
    }

    function grantAccess(address user) external {
        require(msg.sender == admin, "Only admin");
        authorized[user] = true;
    }

    function verifyAccess(uint256 timestamp, uint8 v, bytes32 r, bytes32 s) public view returns (bool) {
        if (block.timestamp > timestamp + expireLimit) {
            return false;
        }

        bytes32 message = keccak256(abi.encodePacked(msg.sender, timestamp, domainSeparator));
        bytes32 ethSigned = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", message));
        address signer = ecrecover(ethSigned, v, r, s);
        return authorized[signer];
    }

    function criticalAction(uint256 timestamp, uint8 v, bytes32 r, bytes32 s) external returns (string memory) {
        bool allowed = verifyAccess(timestamp, v, r, s);
        if (allowed) {
            emit AccessAttempt(msg.sender, true, "Access granted");
            return "Secure critical action executed.";
        } else {
            emit AccessAttempt(msg.sender, false, "Access rejected (timing or auth)");
            revert("Access verification failed");
        }
    }
}

/// @notice Attack contract simulating failure through tight false reject configurations
contract FalseRejectRateIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function tryCriticalAction(uint256 timestamp, uint8 v, bytes32 r, bytes32 s) external returns (bool success, bytes memory result) {
        (success, result) = targetInsecure.call(
            abi.encodeWithSignature("criticalAction(uint256,uint8,bytes32,bytes32)", timestamp, v, r, s)
        );
    }
}
