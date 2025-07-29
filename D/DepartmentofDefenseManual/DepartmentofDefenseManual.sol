// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// DoDManualCompliance contract for managing Department of Defense Manual compliance records
contract DoDManualCompliance {
    // Contract owner (e.g., DoD Office of the Under Secretary of Defense)
    address public owner;

    // Structure to store compliance record
    struct ComplianceRecord {
        bytes32 recordId; // Unique identifier for the record
        address creator; // Address of the entity creating the record
        bytes32 complianceHash; // Hash of compliance data (e.g., supply chain log, security audit)
        string metadataURI; // Off-chain URI for detailed metadata (e.g., IPFS link)
        uint256 createdAt; // Timestamp when record was created
        uint256 updatedAt; // Timestamp of last update
        bool active; // Whether the record is active
    }

    // Structure to store submission metadata for rate limiting
    struct SubmissionInfo {
        uint256 lastSubmissionTimestamp; // Timestamp of last submission
        uint256 submissionCount; // Number of submissions in current window
    }

    // Mapping to store compliance records by record ID
    mapping(bytes32 => ComplianceRecord) public records;

    // Mapping to store authorized entities (e.g., supply chain managers, security officers)
    mapping(address => bool) public authorizedEntities;

    // Mapping to store submission metadata for rate limiting
    mapping(address => SubmissionInfo) public submissionInfo;

    // Rate limit parameters to prevent DoS
    uint256 public constant SUBMISSION_WINDOW = 1 hours; // Time window for rate limiting
    uint256 public constant MAX_SUBMISSIONS_PER_WINDOW = 5; // Max submissions per window
    uint256 public constant MIN_SUBMISSION_INTERVAL = 10 seconds; // Minimum time between submissions

    // Event emitted when a compliance record is registered
    event RecordRegistered(bytes32 indexed recordId, address indexed creator, bytes32 complianceHash, string metadataURI, uint256 timestamp);

    // Event emitted when a compliance record is updated
    event RecordUpdated(bytes32 indexed recordId, bytes32 newComplianceHash, string newMetadataURI, uint256 timestamp);

    // Event emitted when a record is deactivated
    event RecordDeactivated(bytes32 indexed recordId, uint256 timestamp);

    // Event emitted when an entity is authorized or deauthorized
    event EntityAuthorizationUpdated(address indexed entity, bool authorized, uint256 timestamp);

    // Event emitted when rate limit is triggered
    event RateLimitTriggered(address indexed entity, uint256 timestamp);

    // Modifier to restrict functions to the contract owner
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    // Modifier to restrict functions to authorized entities
    modifier onlyAuthorizedEntity() {
        require(authorizedEntities[msg.sender], "Only authorized entities can call this function");
        _;
    }

    // Modifier to check if a record exists and is active
    modifier recordActive(bytes32 recordId) {
        require(records[recordId].active, "Record not active or does not exist");
        _;
    }

    // Constructor to set the owner
    constructor() {
        owner = msg.sender;
        authorizedEntities[msg.sender] = true; // Owner is authorized by default
    }

    // Function to register a new compliance record with rate limiting
    function registerRecord(bytes32 recordId, bytes32 complianceHash, string calldata metadataURI) external onlyAuthorizedEntity {
        require(!records[recordId].active, "Record ID already exists");
        require(bytes(metadataURI).length <= 200, "Metadata URI too long"); // Bound input size

        // Rate limiting
        SubmissionInfo storage entityInfo = submissionInfo[msg.sender];
        if (block.timestamp >= entityInfo.lastSubmissionTimestamp + SUBMISSION_WINDOW) {
            entityInfo.submissionCount = 0;
            entityInfo.lastSubmissionTimestamp = block.timestamp;
        } else {
            require(
                block.timestamp >= entityInfo.lastSubmissionTimestamp + MIN_SUBMISSION_INTERVAL,
                "Submission interval too short"
            );
            require(entityInfo.submissionCount < MAX_SUBMISSIONS_PER_WINDOW, "Submission limit exceeded");
            emit RateLimitTriggered(msg.sender, block.timestamp);
        }

        entityInfo.submissionCount += 1;

        records[recordId] = ComplianceRecord({
            recordId: recordId,
            creator: msg.sender,
            complianceHash: complianceHash,
            metadataURI: metadataURI,
            createdAt: block.timestamp,
            updatedAt: block.timestamp,
            active: true
        });

        emit RecordRegistered(recordId, msg.sender, complianceHash, metadataURI, block.timestamp);
    }

    // Function to update a compliance record
    function updateRecord(bytes32 recordId, bytes32 newComplianceHash, string calldata newMetadataURI)
        external
        onlyAuthorizedEntity
        recordActive(recordId)
    {
        require(bytes(newMetadataURI).length <= 200, "Metadata URI too long");
        require(records[recordId].creator == msg.sender || authorizedEntities[msg.sender], "Not authorized to update");

        records[recordId].complianceHash = newComplianceHash;
        records[recordId].metadataURI = newMetadataURI;
        records[recordId].updatedAt = block.timestamp;

        emit RecordUpdated(recordId, newComplianceHash, newMetadataURI, block.timestamp);
    }

    // Function to deactivate a compliance record
    function deactivateRecord(bytes32 recordId) external onlyOwner recordActive(recordId) {
        records[recordId].active = false;
        emit RecordDeactivated(recordId, block.timestamp);
    }

    // Function to verify a compliance record's hash
    function verifyComplianceHash(bytes32 recordId, bytes32 complianceHash)
        external
        view
        recordActive(recordId)
        returns (bool)
    {
        return records[recordId].complianceHash == complianceHash;
    }

    // Function to get compliance record details
    function getRecordDetails(bytes32 recordId)
        external
        view
        recordActive(recordId)
        returns (
            address creator,
            bytes32 complianceHash,
            string memory metadataURI,
            uint256 createdAt,
            uint256 updatedAt
        )
    {
        require(
            msg.sender == owner ||
            msg.sender == records[recordId].creator ||
            authorizedEntities[msg.sender],
            "Not authorized to view record details"
        );

        ComplianceRecord memory record = records[recordId];
        return (
            record.creator,
            record.complianceHash,
            record.metadataURI,
            record.createdAt,
            record.updatedAt
        );
    }

    // Function to authorize or deauthorize an entity
    function setEntityAuthorization(address entity, bool authorized) external onlyOwner {
        require(entity != address(0), "Entity cannot be zero address");
        require(authorizedEntities[entity] != authorized, "Authorization status already set");

        authorizedEntities[entity] = authorized;
        emit EntityAuthorizationUpdated(entity, authorized, block.timestamp);
    }

    // Function to transfer ownership
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "New owner cannot be zero address");
        authorizedEntities[owner] = false; // Remove old owner as authorized entity
        owner = newOwner;
        authorizedEntities[newOwner] = true; // New owner becomes authorized
        emit EntityAuthorizationUpdated(newOwner, true, block.timestamp);
    }
}