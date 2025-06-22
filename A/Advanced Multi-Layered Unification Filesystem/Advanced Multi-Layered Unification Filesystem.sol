// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AMLUFRegistry — Multi-layered file registration & unification contract
contract AMLUFRegistry {
    address public admin;

    struct FileLayer {
        string cid;           // IPFS, Arweave, or Blob reference
        string contentType;   // e.g. "application/json", "image/png"
        bytes32 hash;         // keccak256 or zkBlob hash
        string metadata;      // optional description
        uint256 timestamp;
    }

    mapping(uint256 => FileLayer[]) public files;
    uint256 public totalFiles;

    event FileCreated(uint256 indexed fileId);
    event LayerAdded(uint256 indexed fileId, uint256 layerIndex, string cid, bytes32 hash);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function createFile() external onlyAdmin returns (uint256) {
        uint256 fileId = totalFiles++;
        emit FileCreated(fileId);
        return fileId;
    }

    function addLayer(
        uint256 fileId,
        string calldata cid,
        string calldata contentType,
        bytes32 hash,
        string calldata metadata
    ) external onlyAdmin {
        files[fileId].push(FileLayer(cid, contentType, hash, metadata, block.timestamp));
        emit LayerAdded(fileId, files[fileId].length - 1, cid, hash);
    }

    function getFile(uint256 fileId) external view returns (FileLayer[] memory) {
        return files[fileId];
    }

    function getLatestHash(uint256 fileId) external view returns (bytes32) {
        FileLayer[] storage layers = files[fileId];
        require(layers.length > 0, "No layers");
        return layers[layers.length - 1].hash;
    }
}
