// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Fake Callback, Replay, Stateless Drift
/// Defense Types: Whitelist, Nonce, Message Hashing

contract ACLReceiver {
    address public trustedSender;

    mapping(bytes32 => bool) public processedMessages;

    event RequestSent(bytes32 indexed requestId, string payload);
    event ResponseReceived(bytes32 indexed requestId, string response);
    event AttackDetected(address indexed attacker, string reason);

    constructor(address _trustedSender) {
        trustedSender = _trustedSender;
    }

    /// Simulate sending a stateless request
    function sendAsyncRequest(string calldata payload) external returns (bytes32) {
        bytes32 requestId = keccak256(abi.encodePacked(msg.sender, payload, block.timestamp));
        emit RequestSent(requestId, payload);
        return requestId;
    }

    /// DEFENSE: Process only valid async responses
    function receiveAsyncResponse(bytes32 requestId, string calldata response) external {
        require(msg.sender == trustedSender, "Untrusted sender");
        require(!processedMessages[requestId], "Replay detected");

        processedMessages[requestId] = true;
        emit ResponseReceived(requestId, response);
    }

    /// ATTACK: Simulate a fake sender with callback injection
    function attackFakeResponse(bytes32 fakeRequestId, string calldata badData) external {
        emit AttackDetected(msg.sender, "Fake callback injection");
        revert("Blocked fake callback");
    }

    /// View response status
    function isProcessed(bytes32 requestId) external view returns (bool) {
        return processedMessages[requestId];
    }
}
