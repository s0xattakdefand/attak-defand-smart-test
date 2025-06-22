// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ExposeAttackDefense - Full Attack and Defense Simulation for Exposure Vulnerabilities in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Contract Vulnerable to Exposure
contract InsecureExposeContract {
    address public admin; // PUBLIC access — BAD
    uint256 public secretNumber; // PUBLIC access — BAD

    event DebugEvent(uint256 leakedSecret); // BAD: leaking secret data

    constructor(uint256 _secret) {
        admin = msg.sender;
        secretNumber = _secret;
    }

    function emitSecret() external {
        emit DebugEvent(secretNumber);
    }

    function criticalFunction() external {
        // No access control — BAD
        secretNumber += 1;
    }
}

/// @notice Secure Contract Fully Hardened Against Exposure
contract SecureExposeContract {
    address public admin;
    bytes32 private hashedSecret;

    event PublicEvent(string action);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor(bytes32 _hashedSecret) {
        admin = msg.sender;
        hashedSecret = _hashedSecret;
    }

    function verifySecret(bytes32 guess) external view returns (bool) {
        return guess == hashedSecret;
    }

    function safeAction() external onlyAdmin {
        emit PublicEvent("Admin action executed"); // No sensitive leak
    }

    fallback() external payable {
        revert("Fallback blocked");
    }
}

/// @notice Attack contract simulating exposure reading attempts
contract ExposureIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function readPublicAdmin() external view returns (address admin) {
        (, bytes memory data) = targetInsecure.staticcall(
            abi.encodeWithSignature("admin()")
        );
        admin = abi.decode(data, (address));
    }

    function readSecretNumber() external view returns (uint256 secret) {
        (, bytes memory data) = targetInsecure.staticcall(
            abi.encodeWithSignature("secretNumber()")
        );
        secret = abi.decode(data, (uint256));
    }

    function emitLeakEvent() external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("emitSecret()")
        );
    }

    function callCriticalFunction() external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("criticalFunction()")
        );
    }
}
