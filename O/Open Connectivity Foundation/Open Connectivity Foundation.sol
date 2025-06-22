// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Cross-Contract Spoofing Attack, Message Injection Attack, Device Identity Drift Attack
/// Defense Types: Device Registration with Identity Proof, Signed Cross-Contract Messaging, Session Nonce and Timestamp Validation

contract OpenConnectivityFoundation {
    address public admin;
    mapping(address => bool) public registeredDevices;
    mapping(bytes32 => bool) public usedMessages;

    event DeviceRegistered(address indexed device);
    event MessageSent(address indexed from, address indexed to, string message);

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    // DEFENSE: Device must be registered
    function registerDevice(address device) external onlyAdmin {
        registeredDevices[device] = true;
        emit DeviceRegistered(device);
    }

    // ATTACK Simulation: unregistered device sends message
    function attackSpoofDevice(address targetDevice, string calldata fakeMessage) external {
        emit MessageSent(msg.sender, targetDevice, fakeMessage);
    }

    // DEFENSE: Secure cross-device message
    function sendMessageSecure(
        address to,
        string calldata message,
        uint256 timestamp,
        uint256 nonce,
        bytes32 messageHash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(registeredDevices[msg.sender], "Sender not registered");
        require(registeredDevices[to], "Receiver not registered");
        require(block.timestamp - timestamp <= 300, "Message too old");
        require(!usedMessages[messageHash], "Message already used");

        bytes32 expectedHash = keccak256(abi.encodePacked(msg.sender, to, message, timestamp, nonce));
        require(expectedHash == messageHash, "Hash mismatch");

        address signer = ecrecover(toEthSignedMessageHash(expectedHash), v, r, s);
        require(signer == msg.sender, "Invalid signature");

        usedMessages[messageHash] = true;

        emit MessageSent(msg.sender, to, message);
    }

    // Helper to mimic Ethereum Signed Message
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    // Helper to generate the expected hash off-chain
    function generateMessageHash(
        address from,
        address to,
        string memory message,
        uint256 timestamp,
        uint256 nonce
    ) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(from, to, message, timestamp, nonce));
    }
}
