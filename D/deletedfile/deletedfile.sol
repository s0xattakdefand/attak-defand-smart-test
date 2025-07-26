// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// DeletedFile contract for managing file metadata and deletion status
contract DeletedFile {
    // Owner of the contract (e.g., administrator or data controller)
    address public owner;

    // Structure to store file metadata
    struct FileRecord {
        bytes32 fileHash; // Hash of the file (e.g., SHA-256 of content)
        address uploader; // Address of the entity uploading the file
        uint256 uploadTimestamp; // Time when file was uploaded
        bool isDeleted; // Flag indicating if file is marked as deleted
        uint256 deletionTimestamp; // Time when file was marked as deleted
        bool exists; // Flag to check if record exists
    }

    // Mapping to store file records by file ID (e.g., hash of file identifier)
    mapping(bytes32 => FileRecord) public fileRecords;

    // Mapping to store access permissions for each file by address
    mapping(bytes32 => mapping(address => bool)) public accessPermissions;

    // Event emitted when a file is uploaded
    event FileUploaded(bytes32 indexed fileId, bytes32 fileHash, address uploader, uint256 timestamp);

    // Event emitted when a file is marked as deleted
    event FileDeleted(bytes32 indexed fileId, address deleter, uint256 timestamp);

    // Event emitted when access is granted to a file
    event AccessGranted(bytes32 indexed fileId, address indexed user, uint256 timestamp);

    // Event emitted when access is revoked
    event AccessRevoked(bytes32 indexed fileId, address indexed user, uint256 timestamp);

    // Modifier to restrict functions to the contract owner
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    // Modifier to check if a file record exists
    modifier fileExists(bytes32 fileId) {
        require(fileRecords[fileId].exists, "File record does not exist");
        _;
    }

    // Modifier to check if a file is not deleted
    modifier notDeleted(bytes32 fileId) {
        require(!fileRecords[fileId].isDeleted, "File is marked as deleted");
        _;
    }

    // Constructor to set the owner
    constructor() {
        owner = msg.sender;
    }

    // Function to upload a file's metadata
    function uploadFile(bytes32 fileId, bytes32 fileHash) external {
        require(!fileRecords[fileId].exists, "File ID already exists");

        fileRecords[fileId] = FileRecord({
            fileHash: fileHash,
            uploader: msg.sender,
            uploadTimestamp: block.timestamp,
            isDeleted: false,
            deletionTimestamp: 0,
            exists: true
        });

        // Grant access to the uploader by default
        accessPermissions[fileId][msg.sender] = true;

        emit FileUploaded(fileId, fileHash, msg.sender, block.timestamp);
    }

    // Function to mark a file as deleted
    function deleteFile(bytes32 fileId) external fileExists(fileId) notDeleted(fileId) {
        require(
            msg.sender == owner || msg.sender == fileRecords[fileId].uploader,
            "Only owner or uploader can delete"
        );

        fileRecords[fileId].isDeleted = true;
        fileRecords[fileId].deletionTimestamp = block.timestamp;

        emit FileDeleted(fileId, msg.sender, block.timestamp);
    }

    // Function to grant access to a file
    function grantAccess(bytes32 fileId, address user) external onlyOwner fileExists(fileId) notDeleted(fileId) {
        require(user != address(0), "Invalid user address");
        require(!accessPermissions[fileId][user], "User already has access");

        accessPermissions[fileId][user] = true;
        emit AccessGranted(fileId, user, block.timestamp);
    }

    // Function to revoke access to a file
    function revokeAccess(bytes32 fileId, address user) external onlyOwner fileExists(fileId) {
        require(accessPermissions[fileId][user], "User does not have access");

        accessPermissions[fileId][user] = false;
        emit AccessRevoked(fileId, user, block.timestamp);
    }

    // Function to verify file hash
    function verifyFile(bytes32 fileId, bytes32 fileHash) external view fileExists(fileId) returns (bool) {
        return fileRecords[fileId].fileHash == fileHash;
    }

    // Function to check file status
    function getFileStatus(bytes32 fileId) external view fileExists(fileId) returns (bool isDeleted, uint256 deletionTimestamp) {
        return (fileRecords[fileId].isDeleted, fileRecords[fileId].deletionTimestamp);
    }

    // Function to retrieve file metadata (only for authorized users)
    function getFileMetadata(bytes32 fileId)
        external
        view
        fileExists(fileId)
        returns (bytes32 fileHash, address uploader, uint256 uploadTimestamp, bool isDeleted)
    {
        require(
            msg.sender == owner || accessPermissions[fileId][msg.sender],
            "Not authorized to view metadata"
        );

        FileRecord memory record = fileRecords[fileId];
        return (record.fileHash, record.uploader, record.uploadTimestamp, record.isDeleted);
    }

    // Function to check if a user has access to a file
    function hasAccess(bytes32 fileId, address user) external view fileExists(fileId) returns (bool) {
        return accessPermissions[fileId][user];
    }

    // Function to transfer ownership
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "New owner cannot be zero address");
        owner = newOwner;
    }
}