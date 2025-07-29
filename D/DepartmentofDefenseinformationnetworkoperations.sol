// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// DoDINOperations contract for secure Department of Defense Information Network Operations
contract DoDINOperations {
    // Contract owner (e.g., DoD Network Operations and Security Center)
    address public owner;

    // Structure to store network operation record
    struct NetworkRecord {
        bytes32 recordId; // Unique identifier for the record
        address creator; // Address of the entity creating the record
        bytes32 dataHash; // Hash of the record data (e.g., configuration, alert)
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

    // Mapping to store network records by record ID
    mapping(bytes32 => NetworkRecord) public records;

    // Mapping to store authorized operators (e.g., NOSC personnel, CND providers)
    mapping(address => bool) public authorizedOperators;

    // Mapping to store submission metadata for rate limiting
    mapping(address => SubmissionInfo) public submissionInfo;

    // Rate limit parameters to prevent DoS
    uint256 public constant SUBMISSION_WINDOW = 1 hours; // Time window for rate limiting
    uint256 public constant MAX_SUBMISSIONS_PER_WINDOW = 5; // Max submissions per window
    uint256 public constant MIN_SUBMISSION_INTERVAL = 10 seconds; // Minimum time between submissions

    // Event emitted when a network record is registered
    event RecordRegistered(bytes32 indexed recordId, address indexed creator, bytes32 dataHash, string metadataURI, uint256 timestamp);

    // Event emitted when a network record is updated
    event RecordUpdated(bytes32 indexed recordId, bytes32 newDataHash, string newMetadataURI, uint256 timestamp);

    // Event emitted when a record is deactivated
    event RecordDeactivated(bytes32 indexed recordId, uint256 timestamp);

    // Event emitted when an operator is authorized or deauthorized
    event OperatorAuthorizationUpdated(address indexed operator, bool authorized, uint256 timestamp);

    // Event emitted when rate limit is triggered
    event RateLimitTriggered(address indexed operator, uint256 timestamp);

    // Modifier to restrict functions to the contract owner
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    // Modifier to restrict functions to authorized operators
    modifier onlyAuthorizedOperator() {
        require(authorizedOperators[msg.sender], "Only authorized operators can call this function");
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
        authorizedOperators[msg.sender] = true; // Owner is authorized by default
    }

    // Function to register a new network operation record with rate limiting
    function registerRecord(bytes32 recordId, bytes32 dataHash, string calldata metadataURI) external onlyAuthorizedOperator {
        require(!records[recordId].active, "Record ID already exists");
        require(bytes(metadataURI).length <= 200, "Metadata URI too long"); // Bound input size

        // Rate limiting
        SubmissionInfo storage operatorInfo = submissionInfo[msg.sender];
        if (block.timestamp >= operatorInfo.lastSubmissionTimestamp + SUBMISSION_WINDOW) {
            operatorInfo.submissionCount = 0;
            operatorInfo.lastSubmissionTimestamp = block.timestamp;
        } else {
            require(
                block.timestamp >= operatorInfo.lastSubmissionTimestamp + MIN_SUBMISSION_INTERVAL,
                "Submission interval too short"
            );
            require(operatorInfo.submissionCount < MAX_SUBMISSIONS_PER_WINDOW, "Submission limit exceeded");
            emit RateLimitTriggered(msg.sender, block.timestamp);
        }

        operatorInfo.submissionCount += 1;

        records[recordId] = NetworkRecord({
            recordId: recordId,
            creator: msg.sender,
            dataHash: dataHash,
            metadataURI: metadataURI,
            createdAt: block.timestamp,
            updatedAt: block.timestamp,
            active: true
        });

        emit RecordRegistered(recordId, msg.sender, dataHash, metadataURI, block.timestamp);
    }

    // Function to update a network operation record
    function updateRecord(bytes32 recordId, bytes32 newDataHash, string calldata newMetadataURI)
        external
        onlyAuthorizedOperator
        recordActive(recordId)
    {
        require(bytes(newMetadataURI).length <= 200, "Metadata URI too long");
        require(records[recordId].creator == msg.sender || authorizedOperators[msg.sender], "Not authorized to update");

        records[recordId].dataHash = newDataHash;
        records[recordId].metadataURI = newMetadataURI;
        records[recordId].updatedAt = block.timestamp;

        emit RecordUpdated(recordId, newDataHash, newMetadataURI, block.timestamp);
    }

    // Function to deactivate a network operation record
    function deactivateRecord(bytes32 recordId) external onlyOwner recordActive(recordId) {
        records[recordId].active = false;
        emit RecordDeactivated(recordId, block.timestamp);
    }

    // Function to verify a record's data hash
    function verifyRecordHash(bytes32 recordId, bytes32 dataHash)
        external
        view
        recordActive(recordId)
        returns (bool)
    {
        return records[recordId].dataHash == dataHash;
    }

    // Function to get record details
    function getRecordDetails(bytes32 recordId)
        external
        view
        recordActive(recordId)
        returns (
            address creator,
            bytes32 dataHash,
            string memory metadataURI,
            uint256 createdAt,
            uint256 updatedAt
        )
    {
        require(
            msg.sender == owner ||
            msg.sender == records[recordId].creator ||
            authorizedOperators[msg.sender],
            "Not authorized to view record details"
        );

        NetworkRecord memory record = records[recordId];
        return (
            record.creator,
            record.dataHash,
            record.metadataURI,
            record.createdAt,
            record.updatedAt
        );
    }

    // Function to authorize or deauthorize an operator
    function setOperatorAuthorization(address operator, bool authorized) external onlyOwner {
        require(operator != address(0), "Operator cannot be zero address");
        require(authorizedOperators[operator] != authorized, "Authorization status already set");

        authorizedOperators[operator] = authorized;
        emit OperatorAuthorizationUpdated(operator, authorized, block.timestamp);
    }

    // Function to transfer ownership
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "New owner cannot be zero address");
        authorizedOperators[owner] = false; // Remove old owner as authorized operator
        owner = newOwner;
        authorizedOperators[newOwner] = true; // New owner becomes authorized
        emit OperatorAuthorizationUpdated(newOwner, true, block.timestamp);
    }
}