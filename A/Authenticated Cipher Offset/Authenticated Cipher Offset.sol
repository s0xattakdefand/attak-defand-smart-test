// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Offset Forgery, Tag Tampering, Replay Injection
/// Defense Types: Tag Check, Offset Binding, Nonce Registry

contract AuthenticatedCipherOffsetEngine {
    address public authorizedSender;

    struct EncryptedMessage {
        bytes32 offsetCipher;   // Offset-bound ciphertext
        bytes32 authTag;        // MAC or zk-generated tag
        uint256 timestamp;
    }

    mapping(bytes32 => bool) public usedTags;
    mapping(bytes32 => EncryptedMessage) public messages;

    event CipherReceived(bytes32 indexed messageId, bytes32 offsetCipher, bytes32 tag);
    event AttackDetected(address indexed attacker, string reason);

    constructor(address _sender) {
        authorizedSender = _sender;
    }

    /// DEFENSE: Accept encrypted message with offset + tag
    function submitEncrypted(bytes32 messageId, bytes32 offsetCipher, bytes32 tag) external {
        require(msg.sender == authorizedSender, "Unauthorized sender");
        require(!usedTags[tag], "Replay detected");

        // Simulate authentication: tag must be keccak256(offsetCipher || messageId)
        bytes32 expectedTag = keccak256(abi.encodePacked(offsetCipher, messageId));
        require(tag == expectedTag, "Tag mismatch: potential forgery");

        usedTags[tag] = true;
        messages[messageId] = EncryptedMessage(offsetCipher, tag, block.timestamp);
        emit CipherReceived(messageId, offsetCipher, tag);
    }

    /// ATTACK: Forged ciphertext or tampered tag
    function attackTamperedCipher(bytes32 messageId, bytes32 fakeCipher, bytes32 fakeTag) external {
        emit AttackDetected(msg.sender, "Tampered tag or offset injection");
        revert("Tampered ACO rejected");
    }

    /// View message
    function getMessage(bytes32 messageId) external view returns (bytes32 offsetCipher, bytes32 tag, uint256 ts) {
        EncryptedMessage memory msgData = messages[messageId];
        return (msgData.offsetCipher, msgData.authTag, msgData.timestamp);
    }
}
