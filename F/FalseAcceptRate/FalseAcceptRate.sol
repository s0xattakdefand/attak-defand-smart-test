// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title FalseAcceptRateAttackDefense - Full Attack and Defense Simulation for False Accept Rate Vulnerabilities in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure FAR Manager (Vulnerable to Loose Acceptance)
contract InsecureFalseAcceptRateManager {
    address public admin;
    bytes32 public domainSeparator;

    constructor() {
        admin = msg.sender;
        domainSeparator = keccak256(abi.encodePacked(address(this), block.chainid));
    }

    function looseVerify(uint8 v, bytes32 r, bytes32 s) public view returns (bool) {
        bytes32 message = keccak256(abi.encodePacked(msg.sender));
        bytes32 ethSigned = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", message));
        address signer = ecrecover(ethSigned, v, r, s);

        return signer != address(0); // BAD: accepts ANY signature that can be recovered
    }

    function criticalAction(uint8 v, bytes32 r, bytes32 s) external view returns (string memory) {
        require(looseVerify(v, r, s), "Access denied");
        return "Insecure critical action executed.";
    }
}

/// @notice Secure FAR Manager (Strict Binding and Tight Validation)
contract SecureFalseAcceptRateManager {
    address public admin;
    bytes32 public domainSeparator;
    uint256 public constant DOMAIN_VERSION = 1;

    event AccessAttempt(address indexed user, bool success, string reason);

    constructor() {
        admin = msg.sender;
        domainSeparator = keccak256(abi.encodePacked(address(this), block.chainid, DOMAIN_VERSION));
    }

    function strictVerify(uint8 v, bytes32 r, bytes32 s) public view returns (bool) {
        bytes32 message = keccak256(abi.encodePacked(msg.sender, domainSeparator));
        bytes32 ethSigned = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", message));
        address signer = ecrecover(ethSigned, v, r, s);

        return signer == admin;
    }

    function criticalAction(uint8 v, bytes32 r, bytes32 s) external returns (string memory) {
        bool authorized = strictVerify(v, r, s);
        if (authorized) {
            emit AccessAttempt(msg.sender, true, "Access granted");
            return "Secure critical action executed!";
        } else {
            emit AccessAttempt(msg.sender, false, "Access denied");
            revert("Unauthorized attempt");
        }
    }
}

/// @notice Attack contract simulating loose acceptance exploitation
contract FalseAcceptRateIntruder {
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
