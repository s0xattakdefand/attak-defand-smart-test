// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CDRRegistry {
    struct Record {
        string label;            // e.g., "My Album", "ZK-Proof-2025"
        string metadataURI;      // IPFS/Arweave CID
        bytes32 contentHash;     // keccak256(data)
        uint256 writtenAt;
        bool exists;
    }

    mapping(address => mapping(uint256 => Record)) public userRecords;

    event CDWritten(address indexed user, uint256 indexed id, string label, bytes32 contentHash);

    function burnCD(uint256 id, string calldata label, string calldata uri, bytes32 contentHash) external {
        require(!userRecords[msg.sender][id].exists, "Already written");

        userRecords[msg.sender][id] = Record({
            label: label,
            metadataURI: uri,
            contentHash: contentHash,
            writtenAt: block.timestamp,
            exists: true
        });

        emit CDWritten(msg.sender, id, label, contentHash);
    }

    function getRecord(address user, uint256 id) external view returns (
        string memory label,
        string memory metadataURI,
        bytes32 contentHash,
        uint256 writtenAt
    ) {
        Record memory r = userRecords[user][id];
        require(r.exists, "Not found");
        return (r.label, r.metadataURI, r.contentHash, r.writtenAt);
    }
}
