// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ExfiltrationAttackDefense - Full Attack and Defense Simulation for Exfiltration Vulnerabilities in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Contract Vulnerable to Exfiltration
contract InsecureExfiltrationContract {
    uint256 public publicValue;
    uint256 private secretValue; // Still accessible through storage inspection

    event ValueLeaked(uint256 secret);

    constructor(uint256 _secret) {
        publicValue = 12345;
        secretValue = _secret;
    }

    function unsafeLeak() external {
        emit ValueLeaked(secretValue); // BAD: Leaking internal data via event
    }

    fallback() external payable {
        // BAD: Accept any fallback call that could force leakage
        emit ValueLeaked(secretValue);
    }

    function getSecretDirect() external view returns (uint256) {
        return secretValue; // BAD: Direct exposure
    }
}

/// @notice Secure Contract Fully Hardened Against Exfiltration
contract SecureExfiltrationContract {
    address public owner;
    uint256 public publicValue;
    bytes32 private hashedSecret;

    event PublicActionLogged(string message);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    constructor(bytes32 _hashedSecret) {
        owner = msg.sender;
        publicValue = 12345;
        hashedSecret = _hashedSecret;
    }

    function verifySecret(bytes32 guess) external view returns (bool) {
        return guess == hashedSecret; // Only verifies without revealing
    }

    fallback() external payable {
        revert("Fallback rejected"); // Reject unknown call payloads
    }

    function logPublicAction() external {
        emit PublicActionLogged("Public action executed"); // No sensitive data leaks
    }
}

/// @notice Attack contract trying to force data exfiltration
contract ExfiltrationIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function tryForceFallback() external returns (bool success) {
        (success, ) = targetInsecure.call{value: 0}("");
    }

    function tryReadSecret() external returns (bool success, bytes memory data) {
        (success, data) = targetInsecure.call(
            abi.encodeWithSignature("getSecretDirect()")
        );
    }

    function tryLeakEvent() external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("unsafeLeak()")
        );
    }
}
