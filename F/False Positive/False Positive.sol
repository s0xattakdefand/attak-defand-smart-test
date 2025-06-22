// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title FalsePositiveAttackDefense - Full Attack and Defense Simulation for False Positive Vulnerabilities in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure False Positive Access Manager (Vulnerable to Lax Validation)
contract InsecureFalsePositiveManager {
    address public admin;
    bytes32 public domainSeparator;

    constructor() {
        admin = msg.sender;
        domainSeparator = keccak256(abi.encodePacked(block.chainid, address(this)));
    }

    function isAuthorized(uint8 v, bytes32 r, bytes32 s) public view returns (bool) {
        bytes32 message = keccak256(abi.encodePacked(msg.sender));
        bytes32 ethSigned = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", message));

        address signer = ecrecover(ethSigned, v, r, s);
        return signer != address(0); // BAD: Accepts ANY valid signer even if not admin
    }

    function criticalAction(uint8 v, bytes32 r, bytes32 s) external view returns (string memory) {
        require(isAuthorized(v, r, s), "Not authorized");
        return "Insecure action allowed!";
    }
}

/// @notice Secure False Positive Protected Manager (Strict Role and Signature Binding)
contract SecureFalsePositiveManager {
    address public admin;
    bytes32 public domainSeparator;
    uint256 public constant DOMAIN_VERSION = 1;

    event AccessAttempt(address indexed user, bool success, string reason);

    constructor() {
        admin = msg.sender;
        domainSeparator = keccak256(abi.encodePacked(block.chainid, address(this), DOMAIN_VERSION));
    }

    function isAuthorized(uint8 v, bytes32 r, bytes32 s) public view returns (bool) {
        bytes32 message = keccak256(abi.encodePacked(msg.sender, domainSeparator));
        bytes32 ethSigned = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", message));
        address signer = ecrecover(ethSigned, v, r, s);
        return signer == admin;
    }

    function criticalAction(uint8 v, bytes32 r, bytes32 s) external returns (string memory) {
        bool allowed = isAuthorized(v, r, s);
        if (allowed) {
            emit AccessAttempt(msg.sender, true, "Authorized action");
            return "Secure critical action executed!";
        } else {
            emit AccessAttempt(msg.sender, false, "Unauthorized access attempt");
            revert("Unauthorized action");
        }
    }
}

/// @notice Attack contract simulating false positive exploitation
contract FalsePositiveIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function tryFakeAction(uint8 v, bytes32 r, bytes32 s) external returns (bool success, bytes memory data) {
        (success, data) = targetInsecure.call(
            abi.encodeWithSignature("criticalAction(uint8,bytes32,bytes32)", v, r, s)
        );
    }
}
