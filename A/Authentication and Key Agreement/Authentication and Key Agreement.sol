// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract AuthKeyAgreement {
    struct Session {
        address initiator;
        address responder;
        bytes32 initiatorPubKey;
        bytes32 responderPubKey;
        bytes32 sessionKey;
        bool isActive;
    }

    mapping(bytes32 => Session) public sessions;
    mapping(address => uint256) public nonces;

    event SessionInitiated(bytes32 indexed sessionId, address initiator, address responder);
    event SessionEstablished(bytes32 indexed sessionId, bytes32 sessionKey);

    modifier validNonce(address user, uint256 nonce) {
        require(nonce == nonces[user], "Invalid nonce");
        _;
        nonces[user]++;
    }

    /// @notice Initiate authentication and key agreement session
    function initiateSession(
        address responder,
        bytes32 initiatorPubKey,
        uint256 nonce
    ) external validNonce(msg.sender, nonce) returns (bytes32) {
        bytes32 sessionId = keccak256(abi.encodePacked(msg.sender, responder, nonce, block.timestamp));
        
        sessions[sessionId] = Session({
            initiator: msg.sender,
            responder: responder,
            initiatorPubKey: initiatorPubKey,
            responderPubKey: bytes32(0),
            sessionKey: bytes32(0),
            isActive: false
        });

        emit SessionInitiated(sessionId, msg.sender, responder);
        return sessionId;
    }

    /// @notice Respond and finalize the key agreement
    function respondSession(
        bytes32 sessionId,
        bytes32 responderPubKey,
        bytes memory initiatorSignature,
        uint256 nonce
    ) external validNonce(msg.sender, nonce) {
        Session storage session = sessions[sessionId];

        require(session.responder == msg.sender, "Unauthorized responder");
        require(session.responderPubKey == bytes32(0), "Already responded");

        // Verify initiator's signature off-chain and pass verification here (simplified for demo)
        bytes32 expectedHash = keccak256(abi.encodePacked(session.initiator, session.responder, session.initiatorPubKey, nonce - 1));
        require(recoverSigner(expectedHash, initiatorSignature) == session.initiator, "Invalid initiator signature");

        session.responderPubKey = responderPubKey;
        session.sessionKey = deriveSharedKey(session.initiatorPubKey, responderPubKey);
        session.isActive = true;

        emit SessionEstablished(sessionId, session.sessionKey);
    }

    /// @notice Derive a shared key (simplified Diffie-Hellman using XOR for demonstration; in practice use proper DH off-chain)
    function deriveSharedKey(bytes32 pubKeyA, bytes32 pubKeyB) internal pure returns (bytes32) {
        return pubKeyA ^ pubKeyB;
    }

    /// @notice Recover signer from signature
    function recoverSigner(bytes32 messageHash, bytes memory signature) internal pure returns (address) {
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(signature);
        return ecrecover(ethSignedMessageHash, v, r, s);
    }

    /// @notice Helper to split signatures
    function splitSignature(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Invalid signature length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }

    /// @notice Get session details
    function getSession(bytes32 sessionId) external view returns (Session memory) {
        return sessions[sessionId];
    }
}
