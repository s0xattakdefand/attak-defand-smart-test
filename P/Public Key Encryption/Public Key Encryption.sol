// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ========== 1️⃣ Public Key Hash Registry ========== */
contract PubKeyRegistry {
    mapping(address => bytes32) public pubKeyHashes;

    function register(bytes32 pubKeyHash) external {
        pubKeyHashes[msg.sender] = pubKeyHash;
    }

    function isValid(address user, bytes32 pubKeyHash) public view returns (bool) {
        return pubKeyHashes[user] == pubKeyHash;
    }
}

/* ========== 2️⃣ Encrypted Message Storage ========== */
contract EncryptedInbox {
    struct CipherPayload {
        bytes32 cipherHash; // e.g., keccak256(ciphertext)
        bytes32 pubKeyHash;
        uint256 timestamp;
    }

    mapping(address => CipherPayload[]) public inbox;

    event MessageSent(address indexed to, bytes32 cipherHash);

    function sendMessage(address to, bytes32 cipherHash, bytes32 pubKeyHash) external {
        inbox[to].push(CipherPayload(cipherHash, pubKeyHash, block.timestamp));
        emit MessageSent(to, cipherHash);
    }

    function getMessage(address to, uint256 i) external view returns (bytes32, bytes32, uint256) {
        CipherPayload memory msg_ = inbox[to][i];
        return (msg_.cipherHash, msg_.pubKeyHash, msg_.timestamp);
    }
}

/* ========== 3️⃣ Message Decryption Auth (via Signature) ========== */
contract DecryptionVerifier {
    event Decrypted(address user, string decryptedMessage);

    function verifyDecryption(bytes32 hash, bytes memory sig, string memory plaintext) external {
        address signer = recover(hash, sig);
        require(signer == msg.sender, "Signature mismatch");
        emit Decrypted(msg.sender, plaintext);
    }

    function recover(bytes32 hash, bytes memory sig) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(sig, (bytes32, bytes32, uint8));
        return ecrecover(hash, v, r, s);
    }
}

/* ========== 4️⃣ zkProof Verification Stub (Mock) ========== */
contract ZKDecryptionProof {
    mapping(bytes32 => bool) public verifiedProofs;

    function verifyZK(bytes32 proofID, bytes calldata zkProof) external {
        // simulate zk validation
        require(zkProof.length > 32, "Invalid proof");
        verifiedProofs[proofID] = true;
    }

    function isVerified(bytes32 proofID) external view returns (bool) {
        return verifiedProofs[proofID];
    }
}
