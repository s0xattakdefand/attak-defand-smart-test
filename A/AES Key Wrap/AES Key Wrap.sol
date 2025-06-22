// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AESKeyWrapCommit — Logs AES-KW result hashes for wrapped keys
contract AESKeyWrapCommit {
    address public admin;

    struct WrappedKey {
        bytes32 wrappedHash; // keccak256(AES_KW_output)
        string label;        // "zkVerifierKey", "BridgeSession", etc.
        address submitter;
        uint256 timestamp;
    }

    WrappedKey[] public keys;

    event KeyWrapped(uint256 indexed id, address indexed submitter, string label, bytes32 wrappedHash);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function submitWrappedKey(bytes32 hash, string calldata label) external returns (uint256) {
        keys.push(WrappedKey(hash, label, msg.sender, block.timestamp));
        uint256 id = keys.length - 1;
        emit KeyWrapped(id, msg.sender, label, hash);
        return id;
    }

    function getWrappedKey(uint256 id) external view returns (WrappedKey memory) {
        return keys[id];
    }

    function totalWrappedKeys() external view returns (uint256) {
        return keys.length;
    }
}
