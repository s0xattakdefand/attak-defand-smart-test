// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AssetIDRegistry — Universal Asset Identification registry
contract AssetIDRegistry {
    address public admin;

    struct Asset {
        string label;          // e.g., "DAO_Property_001"
        bytes32 metadataHash;  // keccak256(metadata JSON)
        address owner;
        string uri;            // IPFS/Arweave
        uint256 timestamp;
        bool active;
    }

    mapping(uint256 => Asset) public assets;
    uint256 public totalAssets;

    event AssetRegistered(uint256 indexed id, string label, address indexed owner);
    event AssetDeactivated(uint256 indexed id);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Admin only");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerAsset(
        string calldata label,
        bytes32 metadataHash,
        string calldata uri,
        address owner
    ) external onlyAdmin returns (uint256) {
        uint256 id = totalAssets++;
        assets[id] = Asset(label, metadataHash, owner, uri, block.timestamp, true);
        emit AssetRegistered(id, label, owner);
        return id;
    }

    function deactivateAsset(uint256 id) external onlyAdmin {
        assets[id].active = false;
        emit AssetDeactivated(id);
    }

    function getAsset(uint256 id) external view returns (Asset memory) {
        return assets[id];
    }

    function verifyAsset(uint256 id, bytes32 metadataHash) external view returns (bool) {
        return assets[id].active && assets[id].metadataHash == metadataHash;
    }
}
