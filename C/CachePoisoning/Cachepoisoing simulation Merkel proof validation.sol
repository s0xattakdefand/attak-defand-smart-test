// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

/**
 * @title PoisonedCache (Vulnerable to Cache Poisoning)
 */
contract PoisonedCache {
    uint256 public cachedValue;
    uint256 public lastUpdated;

    function write(uint256 val) external {
        cachedValue = val; // ❌ No validation, no TTL
        lastUpdated = block.timestamp;
    }

    function read() external view returns (uint256) {
        return cachedValue;
    }
}

/**
 * @title DefendedCache (With ECDSA and TTL)
 */
contract DefendedCache {
    using ECDSA for bytes32;

    address public trustedSigner;
    uint256 public cachedValue;
    uint256 public lastUpdated;
    uint256 public ttl = 10 minutes;

    constructor(address _signer) {
        trustedSigner = _signer;
    }

    function update(uint256 val, bytes calldata sig) external {
        bytes32 hash = keccak256(abi.encodePacked(val, address(this))).toEthSignedMessageHash();
        require(hash.recover(sig) == trustedSigner, "Invalid signature");
        cachedValue = val;
        lastUpdated = block.timestamp;
    }

    function read() external view returns (uint256) {
        require(block.timestamp <= lastUpdated + ttl, "Cache expired");
        return cachedValue;
    }

    function setTTL(uint256 _ttl) external {
        require(msg.sender == trustedSigner, "Only signer");
        ttl = _ttl;
    }
}

/**
 * @title MerkleCacheVerifier (Cache with Merkle Proof Validation)
 */
contract MerkleCacheVerifier {
    bytes32 public currentRoot;
    mapping(bytes32 => bool) public verifiedLeaves;

    event RootUpdated(bytes32 newRoot);
    event LeafVerified(bytes32 leaf);

    function setRoot(bytes32 root) external {
        currentRoot = root;
        emit RootUpdated(root);
    }

    function verifyAndCache(bytes32 leaf, bytes32[] calldata proof) external {
        require(!verifiedLeaves[leaf], "Already verified");
        require(MerkleProof.verify(proof, currentRoot, leaf), "Invalid proof");

        verifiedLeaves[leaf] = true;
        emit LeafVerified(leaf);
    }

    function isVerified(bytes32 leaf) external view returns (bool) {
        return verifiedLeaves[leaf];
    }
}
