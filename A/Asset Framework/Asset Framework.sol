// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AssetFrameworkRegistry — Modular Web3 asset management registry
contract AssetFrameworkRegistry {
    address public admin;

    enum AssetType { FUNGIBLE, NONFUNGIBLE, HYBRID, SYNTHETIC, PHYSICAL }

    struct Asset {
        string name;
        string metadataURI;
        address owner;
        AssetType kind;
        bool active;
        uint256 registeredAt;
    }

    mapping(uint256 => Asset) public assets;
    uint256 public totalAssets;

    event AssetRegistered(uint256 indexed assetId, string name, AssetType kind, address owner);
    event AssetDeactivated(uint256 indexed assetId);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Admin only");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerAsset(
        string calldata name,
        string calldata metadataURI,
        AssetType kind
    ) external returns (uint256) {
        uint256 assetId = totalAssets++;
        assets[assetId] = Asset(name, metadataURI, msg.sender, kind, true, block.timestamp);
        emit AssetRegistered(assetId, name, kind, msg.sender);
        return assetId;
    }

    function deactivateAsset(uint256 assetId) external {
        require(msg.sender == assets[assetId].owner || msg.sender == admin, "Not authorized");
        assets[assetId].active = false;
        emit AssetDeactivated(assetId);
    }

    function getAsset(uint256 assetId) external view returns (Asset memory) {
        return assets[assetId];
    }

    function totalRegisteredAssets() external view returns (uint256) {
        return totalAssets;
    }
}
