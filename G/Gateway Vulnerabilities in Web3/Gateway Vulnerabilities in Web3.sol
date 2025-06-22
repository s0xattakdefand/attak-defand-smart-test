// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title GatewayAttackDefense - Full Attack and Defense Simulation for Gateway Mechanisms in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Gateway (Vulnerable to Injection and Replay Attacks)
contract InsecureGateway {
    event Forwarded(address indexed destination, bytes data);

    function forward(address destination, bytes calldata data) external {
        (bool success, ) = destination.call(data);
        require(success, "Forward failed");

        emit Forwarded(destination, data);
    }
}

/// @notice Secure Gateway (Source Validation + Replay Protection + Payload Verification)
contract SecureGateway {
    address public immutable trustedSource;
    mapping(bytes32 => bool) public usedPayloadHashes;

    event SecureForwarded(address indexed destination, bytes data, bytes32 payloadHash);

    constructor(address _trustedSource) {
        trustedSource = _trustedSource;
    }

    function forward(address destination, bytes calldata data, uint256 nonce, bytes32 expectedHash) external {
        require(msg.sender == trustedSource, "Untrusted source");

        bytes32 computedHash = keccak256(abi.encodePacked(destination, data, nonce, address(this)));
        require(computedHash == expectedHash, "Payload hash mismatch");
        require(!usedPayloadHashes[expectedHash], "Replay detected");

        usedPayloadHashes[expectedHash] = true;

        (bool success, ) = destination.call(data);
        require(success, "Forward failed");

        emit SecureForwarded(destination, data, expectedHash);
    }
}

/// @notice Attack contract simulating Gateway Injection and Spoofing
contract GatewayIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function injectMalicious(address target, bytes memory fakePayload) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("forward(address,bytes)", target, fakePayload)
        );
    }
}
