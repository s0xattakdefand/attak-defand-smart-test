// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title SecureFileSystem
 * @notice A file metadata storage contract with proper access control.
 * Only the file owner or an admin (with the FILE_ADMIN role) may update a file’s metadata.
 */
contract SecureFileSystem is AccessControl {
    bytes32 public constant FILE_ADMIN = keccak256("FILE_ADMIN");

    struct File {
        uint256 id;
        string filename;
        string fileHash;  // Typically a pointer like an IPFS hash
        address owner;
    }

    mapping(uint256 => File) public files;
    uint256 public fileCount;

    event FileCreated(uint256 indexed fileId, string filename, string fileHash, address owner);
    event FileUpdated(uint256 indexed fileId, string filename, string fileHash, address owner);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(FILE_ADMIN, admin);
    }

    /**
     * @notice Create a new file. The caller becomes the owner.
     */
    function createFile(string calldata filename, string calldata fileHash) external {
        fileCount++;
        files[fileCount] = File(fileCount, filename, fileHash, msg.sender);
        emit FileCreated(fileCount, filename, fileHash, msg.sender);
    }

    /**
     * @notice Update a file’s metadata.
     * Only the file owner or an admin can update the file.
     */
    function updateFile(uint256 fileId, string calldata filename, string calldata fileHash) external {
        require(fileId > 0 && fileId <= fileCount, "Invalid file ID");
        File storage f = files[fileId];
        require(msg.sender == f.owner || hasRole(FILE_ADMIN, msg.sender), "Not authorized");
        f.filename = filename;
        f.fileHash = fileHash;
        // Optionally, preserve the original owner
        emit FileUpdated(fileId, filename, fileHash, f.owner);
    }
}
