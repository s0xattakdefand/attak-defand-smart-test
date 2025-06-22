// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title ArchiveRegistry - Immutable on-chain archive record system

contract ArchiveRegistry {
    address public admin;

    struct ArchiveRecord {
        string category;         // e.g., "Proposal", "Snapshot", "Bytecode"
        string referenceLink;    // e.g., IPFS or Arweave link
        bytes32 contentHash;     // keccak256 of original file/data
        string description;      // Optional summary
        uint256 timestamp;
    }

    mapping(bytes32 => ArchiveRecord) public archiveRecords;
    bytes32[] public archiveIndex;

    event Archived(bytes32 indexed archiveId, string category, string referenceLink);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function archive(
        string calldata category,
        string calldata referenceLink,
        bytes32 contentHash,
        string calldata description
    ) external onlyAdmin returns (bytes32 archiveId) {
        archiveId = keccak256(abi.encodePacked(category, contentHash, block.timestamp));
        archiveRecords[archiveId] = ArchiveRecord({
            category: category,
            referenceLink: referenceLink,
            contentHash: contentHash,
            description: description,
            timestamp: block.timestamp
        });
        archiveIndex.push(archiveId);
        emit Archived(archiveId, category, referenceLink);
    }

    function getAllArchives() external view returns (bytes32[] memory) {
        return archiveIndex;
    }

    function getLatestByCategory(string calldata category) external view returns (ArchiveRecord memory) {
        for (uint i = archiveIndex.length; i > 0; i--) {
            bytes32 id = archiveIndex[i - 1];
            if (keccak256(bytes(archiveRecords[id].category)) == keccak256(bytes(category))) {
                return archiveRecords[id];
            }
        }
        revert("No archive for category");
    }
}
