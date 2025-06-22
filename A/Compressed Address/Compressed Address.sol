// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Compressed Address Manager (16-byte key ↔ address)
contract CompressedAddressRegistry {
    address public admin;

    mapping(bytes16 => address) public resolvedAddress;
    mapping(address => bytes16) public compressedKey;

    event AddressCompressed(address original, bytes16 compressed);
    event AddressResolved(bytes16 compressed, address original);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /// Compress using high 16 bytes (unsafe for direct identity unless mapped)
    function compress(address user) public pure returns (bytes16) {
        return bytes16(uint128(uint160(user)));
    }

    /// Register an address with compressed form
    function registerCompressed(address user) external onlyAdmin {
        bytes16 key = compress(user);
        resolvedAddress[key] = user;
        compressedKey[user] = key;
        emit AddressCompressed(user, key);
    }

    function resolve(bytes16 key) external view returns (address) {
        return resolvedAddress[key];
    }

    function getCompressed(address user) external view returns (bytes16) {
        return compressedKey[user];
    }
}
