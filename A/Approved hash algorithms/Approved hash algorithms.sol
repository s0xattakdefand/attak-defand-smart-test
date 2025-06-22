// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract ApprovedHashLibrary {
    event HashComputed(string method, bytes32 result);

    // ✅ EVM-native default
    function computeKeccak256(string calldata input) external returns (bytes32) {
        bytes32 hash = keccak256(abi.encodePacked(input));
        emit HashComputed("keccak256", hash);
        return hash;
    }

    // ✅ Interop with IPFS, BTC, ZK
    function computeSHA256(string calldata input) external returns (bytes32) {
        bytes32 hash = sha256(abi.encodePacked(input));
        emit HashComputed("sha256", hash);
        return hash;
    }

    // ✅ Used in EVM for address derivation (not for new commits)
    function computeRIPEMD160(string calldata input) external returns (bytes20) {
        bytes20 hash = ripemd160(abi.encodePacked(input));
        emit HashComputed("ripemd160", bytes32(uint256(uint160(hash))));
        return hash;
    }

    // 🔐 Domain-separated hash (role binding, commit-reveal, etc.)
    function computeDomainHash(string calldata domain, address user) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(domain, user));
    }

    // ❌ BAD: MD5/SHA1 not allowed in Solidity/EVM
    // These would only be detectable as malicious off-chain signatures

}
