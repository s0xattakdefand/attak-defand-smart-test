// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title PublicKeyAssuranceRegistry - On-chain registry for verified, trusted public keys in Web3 protocols

contract PublicKeyAssuranceRegistry {
    address public admin;

    struct PublicKeyInfo {
        bytes32 id;
        address assertedBy;
        bytes pubkey;             // Raw pubkey bytes (e.g., X, Y coordinates or compressed form)
        string purpose;           // e.g., "BridgeSigner", "ZKVerifier", "OracleRelayer"
        string assuranceLevel;    // e.g., "Verified", "DAO-Attested", "Unverified"
        string comment;
        uint256 timestamp;
    }

    mapping(bytes32 => PublicKeyInfo) public publicKeys;
    bytes32[] public keyIds;

    event PublicKeyRegistered(bytes32 indexed id, string purpose, string assuranceLevel);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerKey(
        bytes calldata pubkey,
        string calldata purpose,
        string calldata assuranceLevel,
        string calldata comment
    ) external onlyAdmin returns (bytes32 id) {
        id = keccak256(abi.encodePacked(pubkey, purpose, block.timestamp));
        publicKeys[id] = PublicKeyInfo({
            id: id,
            assertedBy: msg.sender,
            pubkey: pubkey,
            purpose: purpose,
            assuranceLevel: assuranceLevel,
            comment: comment,
            timestamp: block.timestamp
        });
        keyIds.push(id);
        emit PublicKeyRegistered(id, purpose, assuranceLevel);
        return id;
    }

    function getKey(bytes32 id) external view returns (PublicKeyInfo memory) {
        return publicKeys[id];
    }

    function getAllKeyIds() external view returns (bytes32[] memory) {
        return keyIds;
    }
}
