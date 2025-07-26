// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// DeIdentifiedData contract for managing de-identified information on the blockchain
contract DeIdentifiedData {
    // Owner of the contract (e.g., data controller or organization)
    address public owner;

    // Structure to store de-identified data metadata
    struct DataRecord {
        bytes32 dataHash; // Hash of de-identified data for integrity
        address uploader; // Address of the entity uploading the data
        uint256 timestamp; // Time of data upload
        bool exists; // Flag to check if record exists
    }

    // Structure to store access permissions
    struct AccessPermission {
        bool canAccess; // Whether the address has access
        uint256 grantedAt; // Time when access was granted
    }

    // Mapping to store data records by a unique identifier (e.g., hash of original data ID)
    mapping(bytes32 => DataRecord) public dataRecords;

    // Mapping to store access permissions for each data record by requester address
    mapping(bytes32 => mapping(address => AccessPermission)) public permissions;

    // Event emitted when a new data record is uploaded
    event DataUploaded(bytes32 indexed recordId, bytes32 dataHash, address uploader, uint256 timestamp);

    // Event emitted when access is granted to a requester
    event AccessGranted(bytes32 indexed recordId, address indexed requester, uint256 timestamp);

    // Event emitted when access is revoked
    event AccessRevoked(bytes32 indexed recordId, address indexed requester, uint256 timestamp);

    // Modifier to restrict functions to the contract owner
    modifier onlyOwner() {
        require(msg.sender == owner, "Only the owner can perform this action");
        _;
    }

    // Modifier to check if a record exists
    modifier recordExists(bytes32 recordId) {
        require(dataRecords[recordId].exists, "Data record does not exist");
        _;
    }

    // Constructor to set the contract owner
    constructor() {
        owner = msg.sender;
    }

    // Function to upload a de-identified data hash
    function uploadData(bytes32 recordId, bytes32 dataHash) external {
        require(!dataRecords[recordId].exists, "Data record already exists");
        
        dataRecords[recordId] = DataRecord({
            dataHash: dataHash,
            uploader: msg.sender,
            timestamp: block.timestamp,
            exists: true
        });

        emit DataUploaded(recordId, dataHash, msg.sender, block.timestamp);
    }

    // Function to grant access to a specific address for a data record
    function grantAccess(bytes32 recordId, address requester) external onlyOwner recordExists(recordId) {
        permissions[recordId][requester] = AccessPermission({
            canAccess: true,
            grantedAt: block.timestamp
        });

        emit AccessGranted(recordId, requester, block.timestamp);
    }

    // Function to revoke access from a specific address for a data record
    function revokeAccess(bytes32 recordId, address requester) external onlyOwner recordExists(recordId) {
        require(permissions[recordId][requester].canAccess, "No access permission to revoke");

        permissions[recordId][requester].canAccess = false;
        emit AccessRevoked(recordId, requester, block.timestamp);
    }

    // Function to verify if a provided data hash matches the stored hash
    function verifyData(bytes32 recordId, bytes32 dataHash) external view recordExists(recordId) returns (bool) {
        return dataRecords[recordId].dataHash == dataHash;
    }

    // Function to check if an address has access to a data record
    function hasAccess(bytes32 recordId, address requester) external view recordExists(recordId) returns (bool) {
        return permissions[recordId][requester].canAccess;
    }

    // Function to retrieve data record metadata (only for authorized users)
    function getDataRecord(bytes32 recordId) external view recordExists(recordId) returns (bytes32, address, uint256) {
        require(
            msg.sender == owner || permissions[recordId][msg.sender].canAccess,
            "Not authorized to view this data"
        );
        
        DataRecord memory record = dataRecords[recordId];
        return (record.dataHash, record.uploader, record.timestamp);
    }

    // Function to transfer ownership of the contract
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "New owner cannot be the zero address");
        owner = newOwner;
    }
}