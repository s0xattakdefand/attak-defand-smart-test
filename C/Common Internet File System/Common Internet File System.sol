// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CIFSAccessRegistry {
    address public admin;

    struct File {
        bytes32 fileHash;         // keccak256(IPFS CID or Arweave TX ID)
        address owner;
        mapping(address => bool) readers;
        mapping(address => bool) writers;
    }

    mapping(bytes32 => File) private files;
    mapping(bytes32 => bool) private fileExists;

    event FileRegistered(bytes32 indexed fileId, address indexed owner, bytes32 fileHash);
    event AccessGranted(bytes32 indexed fileId, address indexed user, string accessType);
    event AccessRevoked(bytes32 indexed fileId, address indexed user, string accessType);
    event FileAccessed(bytes32 indexed fileId, address indexed accessor, string method);

    modifier onlyAdmin() {
        require(msg.sender == admin, "CIFS: Not admin");
        _;
    }

    modifier onlyOwner(bytes32 fileId) {
        require(files[fileId].owner == msg.sender, "CIFS: Not file owner");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerFile(bytes32 fileId, bytes32 fileHash) external {
        require(!fileExists[fileId], "CIFS: File already exists");
        fileExists[fileId] = true;

        File storage f = files[fileId];
        f.fileHash = fileHash;
        f.owner = msg.sender;

        emit FileRegistered(fileId, msg.sender, fileHash);
    }

    function grantAccess(bytes32 fileId, address user, string calldata accessType) external onlyOwner(fileId) {
        if (keccak256(bytes(accessType)) == keccak256("read")) {
            files[fileId].readers[user] = true;
        } else if (keccak256(bytes(accessType)) == keccak256("write")) {
            files[fileId].writers[user] = true;
        } else {
            revert("CIFS: Invalid access type");
        }
        emit AccessGranted(fileId, user, accessType);
    }

    function revokeAccess(bytes32 fileId, address user, string calldata accessType) external onlyOwner(fileId) {
        if (keccak256(bytes(accessType)) == keccak256("read")) {
            files[fileId].readers[user] = false;
        } else if (keccak256(bytes(accessType)) == keccak256("write")) {
            files[fileId].writers[user] = false;
        } else {
            revert("CIFS: Invalid access type");
        }
        emit AccessRevoked(fileId, user, accessType);
    }

    function accessFile(bytes32 fileId, string calldata method) external view returns (bytes32) {
        if (keccak256(bytes(method)) == keccak256("read")) {
            require(files[fileId].readers[msg.sender], "CIFS: No read access");
        } else if (keccak256(bytes(method)) == keccak256("write")) {
            require(files[fileId].writers[msg.sender], "CIFS: No write access");
        } else {
            revert("CIFS: Invalid method");
        }
        emit FileAccessed(fileId, msg.sender, method);
        return files[fileId].fileHash;
    }

    function getFileHash(bytes32 fileId) external view returns (bytes32) {
        return files[fileId].fileHash;
    }

    function isReader(bytes32 fileId, address user) external view returns (bool) {
        return files[fileId].readers[user];
    }

    function isWriter(bytes32 fileId, address user) external view returns (bool) {
        return files[fileId].writers[user];
    }
}
