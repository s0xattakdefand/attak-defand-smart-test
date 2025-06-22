// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title ArchitectureDescriptionRegistry - On-chain registry for protocol design metadata

contract ArchitectureDescriptionRegistry {
    address public admin;

    struct Description {
        string systemName;
        string version;
        string upgradePath;      // e.g., UUPS, Multisig, DAO
        string governanceModel;  // e.g., Role-based, token voting
        string componentDiagram; // Link to visual diagram (e.g., IPFS, Arweave)
        bytes32 metadataHash;    // keccak256 of full description markdown
        uint256 timestamp;
    }

    mapping(bytes32 => Description) public architectureVersions;
    bytes32[] public versionHistory;

    event DescriptionRegistered(bytes32 indexed versionId, string systemName, string version);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerDescription(
        string calldata systemName,
        string calldata version,
        string calldata upgradePath,
        string calldata governanceModel,
        string calldata componentDiagram,
        bytes32 metadataHash
    ) external onlyAdmin returns (bytes32 versionId) {
        versionId = keccak256(abi.encodePacked(systemName, version, block.timestamp));
        architectureVersions[versionId] = Description({
            systemName: systemName,
            version: version,
            upgradePath: upgradePath,
            governanceModel: governanceModel,
            componentDiagram: componentDiagram,
            metadataHash: metadataHash,
            timestamp: block.timestamp
        });
        versionHistory.push(versionId);
        emit DescriptionRegistered(versionId, systemName, version);
    }

    function getVersionCount() external view returns (uint256) {
        return versionHistory.length;
    }

    function getLatestVersion() external view returns (Description memory) {
        require(versionHistory.length > 0, "No versions");
        return architectureVersions[versionHistory[versionHistory.length - 1]];
    }
}
