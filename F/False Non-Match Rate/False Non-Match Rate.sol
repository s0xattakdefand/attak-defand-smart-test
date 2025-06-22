// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title FalseNonMatchRateAttackDefense - Full Attack and Defense Simulation for False Non-Match Rate Vulnerabilities in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Validator (High False Non-Match Risk from Entropy and Drift)
contract InsecureFalseNonMatchRateManager {
    address public admin;
    bytes32 public domainSeparator;

    constructor() {
        admin = msg.sender;
        domainSeparator = keccak256(abi.encodePacked(block.chainid, address(this)));
    }

    function verifyIdentity(uint256 timestamp, uint8 v, bytes32 r, bytes32 s) public view returns (bool) {
        bytes32 message = keccak256(abi.encodePacked(msg.sender, timestamp)); // BAD: No domain separator
        bytes32 ethSigned = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", message));
        address recovered = ecrecover(ethSigned, v, r, s);

        return recovered == admin;
    }

    function criticalAction(uint256 timestamp, uint8 v, bytes32 r, bytes32 s) external view returns (string memory) {
        require(verifyIdentity(timestamp, v, r, s), "Verification failed (false non-match)");
        return "Insecure action allowed.";
    }
}

/// @notice Secure Validator (Flexible, Robust Against False Non-Matches)
contract SecureFalseNonMatchRateManager {
    address public admin;
    bytes32 public domainSeparator;
    uint256 public expireWindow = 90; // 90 seconds allowance for drift

    event VerificationAttempt(address indexed user, bool success, string reason);

    constructor() {
        admin = msg.sender;
        domainSeparator = keccak256(abi.encodePacked(block.chainid, address(this), "v1"));
    }

    function verifyIdentity(uint256 timestamp, uint8 v, bytes32 r, bytes32 s) public view returns (bool) {
        if (block.timestamp > timestamp + expireWindow) {
            return false;
        }

        bytes32 message = keccak256(abi.encodePacked(msg.sender, timestamp, domainSeparator));
        bytes32 ethSigned = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", message));
        address recovered = ecrecover(ethSigned, v, r, s);

        return recovered == admin;
    }

    function criticalAction(uint256 timestamp, uint8 v, bytes32 r, bytes32 s) external returns (string memory) {
        bool allowed = verifyIdentity(timestamp, v, r, s);

        if (allowed) {
            emit VerificationAttempt(msg.sender, true, "Access granted");
            return "Secure critical action executed.";
        } else {
            emit VerificationAttempt(msg.sender, false, "Verification rejected (possible false non-match)");
            revert("Access verification failed");
        }
    }
}

/// @notice Attack contract simulating entropy drift causing false non-matches
contract FalseNonMatchRateIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function attemptCriticalAction(uint256 timestamp, uint8 v, bytes32 r, bytes32 s) external returns (bool success, bytes memory data) {
        (success, data) = targetInsecure.call(
            abi.encodeWithSignature("criticalAction(uint256,uint8,bytes32,bytes32)", timestamp, v, r, s)
        );
    }
}
