// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Automated Cryptographic Validation Protocol (ACVP)
contract ACVP {
    address public admin;
    bytes32 public merkleRoot;
    mapping(bytes32 => bool) public usedHashes;

    event SignatureVerified(address signer);
    event HashValidated(bytes32 hash);
    event MerkleProofValidated(address user);

    constructor(bytes32 _root) {
        admin = msg.sender;
        merkleRoot = _root;
    }

    /// ECDSA signature check
    function validateSignature(bytes32 messageHash, bytes calldata signature) external view returns (address) {
        bytes32 ethSigned = toEthSignedMessageHash(messageHash);
        return recover(ethSigned, signature);
    }

    /// Validate hash commitment (preimage match)
    function validateHash(bytes32 preimage, bytes32 expectedHash) external returns (bool) {
        require(keccak256(abi.encodePacked(preimage)) == expectedHash, "Invalid preimage");
        require(!usedHashes[expectedHash], "Already used");
        usedHashes[expectedHash] = true;
        emit HashValidated(expectedHash);
        return true;
    }

    /// Merkle Proof validation (simple inclusion check)
    function validateMerkleProof(
        bytes32[] calldata proof,
        bytes32 leaf
    ) external view returns (bool valid) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            computedHash = keccak256(abi.encodePacked(
                computedHash < proof[i] ? computedHash : proof[i],
                computedHash < proof[i] ? proof[i] : computedHash
            ));
        }
        require(computedHash == merkleRoot, "Invalid Merkle proof");
        return true;
    }

    /// --- Internal cryptographic functions ---
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    function recover(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "Invalid signature");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return ecrecover(hash, v, r, s);
    }
}
