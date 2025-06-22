// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title ValidityAssurance - Verifies and logs validity of cryptographic assertions in Web3

contract ValidityAssurance {
    address public admin;

    struct ValidityRecord {
        bytes32 id;
        address validator;
        string category;         // e.g., "Signature", "ZKProof", "Vote", "Credential"
        string summary;
        bool valid;
        uint256 timestamp;
    }

    mapping(bytes32 => ValidityRecord) public records;
    bytes32[] public recordIds;

    event ValidityChecked(bytes32 indexed id, string category, bool valid);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function recordValidity(
        string calldata category,
        string calldata summary,
        bool valid
    ) external onlyAdmin returns (bytes32 id) {
        id = keccak256(abi.encodePacked(category, summary, block.timestamp));
        records[id] = ValidityRecord({
            id: id,
            validator: msg.sender,
            category: category,
            summary: summary,
            valid: valid,
            timestamp: block.timestamp
        });
        recordIds.push(id);
        emit ValidityChecked(id, category, valid);
        return id;
    }

    function getValidity(bytes32 id) external view returns (ValidityRecord memory) {
        return records[id];
    }

    function getAllValidityIds() external view returns (bytes32[] memory) {
        return recordIds;
    }
}
