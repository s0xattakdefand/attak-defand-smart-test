// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title CacheEnhancedFileSystem
 * @notice An extension to a secure file system that adds caching for quick file lookup by filename.
 */
contract CacheEnhancedFileSystem is AccessControl {
    bytes32 public constant FILE_ADMIN = keccak256("FILE_ADMIN");

    struct File {
        uint256 id;
        string filename;
        string fileHash;
        address owner;
    }

    // Mapping from file ID to file metadata
    mapping(uint256 => File) public files;
    // Mapping from keccak256 hash of filename to file ID for quick lookup
    mapping(bytes32 => uint256) public filenameToFileId;
    uint256 public fileCount;

    event FileCreated(uint256 indexed fileId, string filename, string fileHash, address owner);
    event FileUpdated(uint256 indexed fileId, string filename, string fileHash, address owner);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(FILE_ADMIN, admin);
    }

    function createFile(string calldata filename, string calldata fileHash) external {
        fileCount++;
        files[fileCount] = File(fileCount, filename, fileHash, msg.sender);
        filenameToFileId[keccak256(abi.encodePacked(filename))] = fileCount;
        emit FileCreated(fileCount, filename, fileHash, msg.sender);
    }

    function updateFile(uint256 fileId, string calldata filename, string calldata fileHash) external {
        require(fileId > 0 && fileId <= fileCount, "Invalid file ID");
        File storage f = files[fileId];
        require(msg.sender == f.owner || hasRole(FILE_ADMIN, msg.sender), "Not authorized");
        f.filename = filename;
        f.fileHash = fileHash;
        filenameToFileId[keccak256(abi.encodePacked(filename))] = fileId;
        emit FileUpdated(fileId, filename, fileHash, f.owner);
    }

    function getFileByName(string calldata filename) external view returns (File memory) {
        uint256 id = filenameToFileId[keccak256(abi.encodePacked(filename))];
        require(id != 0, "File not found");
        return files[id];
    }
}
