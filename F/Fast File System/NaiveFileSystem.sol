// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title NaiveFileSystem
 * @notice A naïve file metadata storage contract.
 * This contract lets anyone create or update file entries without restrictions,
 * which is vulnerable to unauthorized modifications.
 */
contract NaiveFileSystem {
    struct File {
        uint256 id;
        string filename;
        string fileHash;  // Could be an IPFS hash or similar pointer
        address owner;
    }

    // Mapping of file ID to file metadata
    mapping(uint256 => File) public files;
    // Counter for file IDs
    uint256 public fileCount;

    event FileCreated(uint256 indexed fileId, string filename, string fileHash, address owner);
    event FileUpdated(uint256 indexed fileId, string filename, string fileHash, address owner);

    /**
     * @notice Create a file entry with the given metadata.
     * No access restrictions: anyone can create a file.
     */
    function createFile(string calldata filename, string calldata fileHash) external {
        fileCount++;
        files[fileCount] = File(fileCount, filename, fileHash, msg.sender);
        emit FileCreated(fileCount, filename, fileHash, msg.sender);
    }

    /**
     * @notice Update an existing file entry.
     * No ownership check – any caller can update any file.
     */
    function updateFile(uint256 fileId, string calldata filename, string calldata fileHash) external {
        require(fileId > 0 && fileId <= fileCount, "Invalid file ID");
        // Vulnerability: No owner check – allows arbitrary modification
        files[fileId] = File(fileId, filename, fileHash, msg.sender);
        emit FileUpdated(fileId, filename, fileHash, msg.sender);
    }
}
