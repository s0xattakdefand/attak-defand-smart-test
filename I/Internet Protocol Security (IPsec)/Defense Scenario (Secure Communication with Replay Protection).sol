pragma solidity ^0.8.21;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SecureChannel {
    using ECDSA for bytes32;

    address public trustedSigner;
    mapping(bytes32 => bool) public processedMessages;

    event ActionExecuted(address indexed executor, bytes32 messageHash);

    constructor(address _trustedSigner) {
        trustedSigner = _trustedSigner;
    }

    modifier onlyNewMessage(bytes32 messageHash) {
        require(!processedMessages[messageHash], "Replay attack detected");
        _;
    }

    function executeAction(
        address executor,
        uint256 nonce,
        bytes memory actionData,
        bytes memory signature
    ) external onlyNewMessage(keccak256(abi.encodePacked(executor, nonce, actionData))) {
        bytes32 messageHash = keccak256(abi.encodePacked(executor, nonce, actionData));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();

        address recoveredSigner = ethSignedMessageHash.recover(signature);
        require(recoveredSigner == trustedSigner, "Invalid signer");

        processedMessages[messageHash] = true;

        // Execute sensitive actions here (decode and use actionData as needed)

        emit ActionExecuted(executor, messageHash);
    }

    function updateTrustedSigner(address newSigner) external {
        require(msg.sender == trustedSigner, "Unauthorized");
        trustedSigner = newSigner;
    }
}
