// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Layer2ForwardingAttackDefense - Full Attack and Defense Simulation for Layer2 Forwarding in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Layer2 Forwarding (No Source Check, No Replay Protection)
contract InsecureLayer2Forwarder {
    mapping(bytes32 => bool) public forwardedMessages;

    event ForwardedMessage(address indexed relayer, bytes32 messageHash, bytes data);

    function forward(bytes calldata data) external {
        bytes32 messageHash = keccak256(data);

        // BAD: Anyone can forward any arbitrary data without origin or replay checks
        forwardedMessages[messageHash] = true;
        emit ForwardedMessage(msg.sender, messageHash, data);
    }
}

/// @notice Secure Layer2 Forwarding (Source Verification + Nonce Protection + Hash Commitment)
contract SecureLayer2Forwarder {
    address public immutable trustedSource;
    mapping(bytes32 => bool) public processedMessages;

    event SecureForwardedMessage(address indexed relayer, bytes32 indexed messageHash, bytes data);

    constructor(address _trustedSource) {
        trustedSource = _trustedSource;
    }

    function secureForward(bytes calldata data, bytes32 expectedHash, uint256 nonce) external {
        require(msg.sender == trustedSource, "Untrusted L2 forwarder");
        
        bytes32 messageHash = keccak256(abi.encodePacked(data, nonce, address(this)));
        require(messageHash == expectedHash, "Hash mismatch");
        require(!processedMessages[messageHash], "Replay detected");

        processedMessages[messageHash] = true;
        emit SecureForwardedMessage(msg.sender, messageHash, data);
    }
}

/// @notice Attack contract simulating Layer2 message injection and replay
contract Layer2ForwarderIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function fakeForward(bytes calldata fakeData) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("forward(bytes)", fakeData)
        );
    }
}
