// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SecureMessageStorage {
    struct EncryptedMessage {
        address sender;
        bytes encryptedData;
    }

    mapping(uint256 => EncryptedMessage) public messages;
    uint256 public messageCount;

    event MessageStored(uint256 messageId, address indexed sender);

    function storeEncryptedMessage(bytes calldata encryptedData) external {
        messages[messageCount] = EncryptedMessage({
            sender: msg.sender,
            encryptedData: encryptedData
        });

        emit MessageStored(messageCount, msg.sender);
        messageCount++;
    }

    function getEncryptedMessage(uint256 messageId) external view returns (bytes memory) {
        require(messageId < messageCount, "Message does not exist.");
        return messages[messageId].encryptedData;
    }
}
