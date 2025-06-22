// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title IntegrityAssuranceRegistry - Tracks and validates the integrity of data, code, proofs, or state in Web3 systems

contract IntegrityAssuranceRegistry {
    address public admin;

    struct IntegrityRecord {
        bytes32 id;
        string category;           // e.g., "Code", "Proof", "Data", "Snapshot"
        bytes32 expectedHash;      // Hash of the verified artifact
        string description;        // What this protects (e.g., "Vault.v3", "zkProof circuit 0x01")
        uint256 issuedAt;
        address issuer;
    }

    mapping(bytes32 => IntegrityRecord) public records;
    bytes32[] public recordIds;

    event IntegrityRegistered(bytes32 indexed id, string category, bytes32 hash);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Admin only");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerIntegrity(
        string calldata category,
        bytes32 expectedHash,
        string calldata description
    ) external onlyAdmin returns (bytes32 id) {
        id = keccak256(abi.encodePacked(category, expectedHash, block.timestamp));
        records[id] = IntegrityRecord({
            id: id,
            category: category,
            expectedHash: expectedHash,
            description: description,
            issuedAt: block.timestamp,
            issuer: msg.sender
        });
        recordIds.push(id);
        emit IntegrityRegistered(id, category, expectedHash);
        return id;
    }

    function verify(bytes32 id, bytes32 actualHash) external view returns (bool) {
        IntegrityRecord memory r = records[id];
        return r.expectedHash == actualHash;
    }

    function getAllIds() external view returns (bytes32[] memory) {
        return recordIds;
    }
}
