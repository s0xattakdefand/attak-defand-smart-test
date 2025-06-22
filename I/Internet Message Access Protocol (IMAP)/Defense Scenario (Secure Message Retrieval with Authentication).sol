pragma solidity ^0.8.21;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SecureMessaging {
    using ECDSA for bytes32;

    address public admin;

    mapping(address => string[]) private inbox;
    mapping(bytes32 => bool) private processedMessages;

    event MessageStored(address indexed recipient, uint256 messageId);
    event MessageRetrieved(address indexed recipient, uint256 messageId);

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    function storeMessage(address recipient, string memory message) external onlyAdmin {
        inbox[recipient].push(message);
        emit MessageStored(recipient, inbox[recipient].length - 1);
    }

    function retrieveMessage(uint256 messageId, bytes memory signature) external view returns (string memory) {
        require(messageId < inbox[msg.sender].length, "Invalid messageId");

        bytes32 messageHash = keccak256(abi.encodePacked(msg.sender, messageId, inbox[msg.sender][messageId]));
        address recoveredSigner = messageHash.toEthSignedMessageHash().recover(signature);

        require(recoveredSigner == msg.sender, "Unauthorized retrieval");

        return inbox[msg.sender][messageId];
    }

    function getInboxSize(address recipient) external view returns (uint256) {
        return inbox[recipient].length;
    }
}
