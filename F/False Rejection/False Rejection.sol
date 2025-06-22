// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title FalseRejectionAttackDefense - Full Attack and Defense Simulation for False Rejection Vulnerabilities in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Access Manager (Vulnerable to False Rejection Drift)
contract InsecureFalseRejectionManager {
    mapping(address => bool) public authorized;
    bytes32 public domainSeparator;

    constructor() {
        domainSeparator = keccak256(abi.encodePacked(block.chainid, address(this)));
        authorized[msg.sender] = true;
    }

    function verifyAccess(uint8 v, bytes32 r, bytes32 s) external view returns (bool) {
        bytes32 message = keccak256(abi.encodePacked(msg.sender, address(this)));
        bytes32 ethSigned = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", message));

        address signer = ecrecover(ethSigned, v, r, s);
        return authorized[signer];
    }

    function criticalAction(uint8 v, bytes32 r, bytes32 s) external view returns (string memory) {
        require(verifyAccess(v, r, s), "Rejected");
        return "Accessed critical action!";
    }
}

/// @notice Secure Access Manager (Fully Hardened Against False Rejection)
contract SecureFalseRejectionManager {
    mapping(address => bool) public authorized;
    bytes32 public domainSeparator;
    uint256 public constant DOMAIN_VERSION = 1;

    event AccessGranted(address indexed user);
    event AccessRevoked(address indexed user);
    event AccessAttempt(address indexed user, bool success, string reason);

    constructor() {
        domainSeparator = keccak256(abi.encodePacked(block.chainid, address(this), DOMAIN_VERSION));
        authorized[msg.sender] = true;
    }

    function grantAccess(address user) external {
        require(user != address(0), "Zero address");
        authorized[user] = true;
        emit AccessGranted(user);
    }

    function revokeAccess(address user) external {
        authorized[user] = false;
        emit AccessRevoked(user);
    }

    function verifyAccess(uint8 v, bytes32 r, bytes32 s) public view returns (bool) {
        bytes32 message = keccak256(abi.encodePacked(msg.sender, domainSeparator));
        bytes32 ethSigned = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", message));
        address signer = ecrecover(ethSigned, v, r, s);
        return authorized[signer];
    }

    function criticalAction(uint8 v, bytes32 r, bytes32 s) external returns (string memory) {
        bool allowed = verifyAccess(v, r, s);
        if (allowed) {
            emit AccessAttempt(msg.sender, true, "Access granted");
            return "Accessed critical action safely!";
        } else {
            emit AccessAttempt(msg.sender, false, "Access rejected");
            revert("Access verification failed");
        }
    }
}

/// @notice Attack contract simulating forced false rejections
contract FalseRejectionIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function tryCriticalAction(uint8 v, bytes32 r, bytes32 s) external returns (bool success, bytes memory result) {
        (success, result) = targetInsecure.call(
            abi.encodeWithSignature("criticalAction(uint8,bytes32,bytes32)", v, r, s)
        );
    }
}
