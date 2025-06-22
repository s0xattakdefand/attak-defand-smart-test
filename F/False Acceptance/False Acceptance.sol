// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title FalseAcceptanceAttackDefense - Full Attack and Defense Simulation for False Acceptance Vulnerabilities in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure False Acceptance Manager (Vulnerable to Spoofed Validation)
contract InsecureFalseAcceptanceManager {
    address public admin;
    bytes32 public domainSeparator;

    constructor() {
        admin = msg.sender;
        domainSeparator = keccak256(abi.encodePacked(address(this), block.chainid));
    }

    function verifyAccess(uint8 v, bytes32 r, bytes32 s) public view returns (bool) {
        bytes32 message = keccak256(abi.encodePacked(msg.sender)); // BAD: No binding to domain or version
        bytes32 ethSigned = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", message));
        address recovered = ecrecover(ethSigned, v, r, s);

        return recovered != address(0); // BAD: accepts ANY valid signer
    }

    function criticalAction(uint8 v, bytes32 r, bytes32 s) external view returns (string memory) {
        require(verifyAccess(v, r, s), "Access denied");
        return "Insecure critical action executed.";
    }
}

/// @notice Secure False Acceptance Manager (Full Binding and Strict Validation)
contract SecureFalseAcceptanceManager {
    address public admin;
    bytes32 public domainSeparator;
    uint256 public constant DOMAIN_VERSION = 1;

    event AccessAttempt(address indexed user, bool success, string reason);

    constructor() {
        admin = msg.sender;
        domainSeparator = keccak256(abi.encodePacked(address(this), block.chainid, DOMAIN_VERSION));
    }

    function verifyAccess(uint8 v, bytes32 r, bytes32 s) public view returns (bool) {
        bytes32 message = keccak256(abi.encodePacked(msg.sender, domainSeparator));
        bytes32 ethSigned = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", message));
        address recovered = ecrecover(ethSigned, v, r, s);

        return recovered == admin;
    }

    function criticalAction(uint8 v, bytes32 r, bytes32 s) external returns (string memory) {
        bool authorized = verifyAccess(v, r, s);
        if (authorized) {
            emit AccessAttempt(msg.sender, true, "Access granted");
            return "Secure critical action executed!";
        } else {
            emit AccessAttempt(msg.sender, false, "Access denied");
            revert("Unauthorized attempt");
        }
    }
}

/// @notice Attack contract simulating false acceptance exploitation
contract FalseAcceptanceIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function spoofCriticalAction(uint8 v, bytes32 r, bytes32 s) external returns (bool success, bytes memory data) {
        (success, data) = targetInsecure.call(
            abi.encodeWithSignature("criticalAction(uint8,bytes32,bytes32)", v, r, s)
        );
    }
}
