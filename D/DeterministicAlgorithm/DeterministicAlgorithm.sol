// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// DeterministicAlgorithm contract for demonstrating deterministic computations
contract DeterministicAlgorithm {
    // Contract owner (e.g., Agency Computation Office)
    address public immutable owner;

    // Structure to store record with deterministic ID
    struct Record {
        bytes32 recordId; // Deterministic ID generated using keccak256
        address creator; // Address of the entity creating the record
        bytes32 inputHash; // Hash of input data used for ID generation
        string metadataURI; // Off-chain URI for detailed metadata (e.g., IPFS link)
        uint256 timestamp; // Timestamp of record creation
        RecordStatus status; // Status of the record
        address reviewer; // Address of the entity reviewing the record
    }

    // Enum for record status
    enum RecordStatus { Pending, Verified, Rejected }

    // Structure to store submission metadata for rate limiting
    struct SubmissionInfo {
        uint256 lastSubmissionTimestamp; // Timestamp of last submission
        uint256 submissionCount; // Number of submissions in current window
    }

    // Mapping to store records by record ID
    mapping(bytes32 => Record) public records;

    // Mapping to store authorized reviewers (e.g., agency officials)
    mapping(address => bool) public authorizedReviewers;

    // Mapping to store submission metadata for rate limiting
    mapping(address => SubmissionInfo) public submissionInfo;

    // Rate limit parameters to prevent DoS
    uint256 public constant SUBMISSION_WINDOW = 1 hours; // Time window for rate limiting
    uint256 public constant MAX_SUBMISSIONS_PER_WINDOW = 5; // Max submissions per window
    uint256 public constant MIN_SUBMISSION_INTERVAL = 10 seconds; // Minimum time between submissions

    // Event emitted when a record is submitted with deterministic ID
    event RecordSubmitted(
        bytes32 indexed recordId,
        address indexed creator,
        bytes32 inputHash,
        string metadataURI,
        uint256 timestamp
    );

    // Event emitted when a record is processed (verified or rejected)
    event RecordProcessed(
        bytes32 indexed recordId,
        RecordStatus status,
        address indexed reviewer,
        uint256 timestamp,
        string reason
    );

    // Event emitted when a reviewer is authorized or deauthorized
    event ReviewerAuthorizationUpdated(address indexed reviewer, bool authorized, uint256 timestamp);

    // Event emitted when rate limit is triggered
    event RateLimitTriggered(address indexed entity, uint256 timestamp);

    // Modifier to restrict functions to the contract owner
    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert("Only owner can call this function");
        }
        _;
    }

    // Modifier to restrict functions to authorized reviewers
    modifier onlyAuthorizedReviewer() {
        if (!authorizedReviewers[msg.sender]) {
            revert("Only authorized reviewers can call this function");
        }
        _;
    }

    // Modifier to check if a record is pending
    modifier recordPending(bytes32 recordId) {
        if (records[recordId].status != RecordStatus.Pending) {
            revert("Record not pending or does not exist");
        }
        _;
    }

    // Constructor to set the immutable owner
    constructor() {
        owner = msg.sender;
        authorizedReviewers[msg.sender] = true; // Owner is authorized by default
    }

    // Function to submit a record with deterministic ID generation and rate limiting
    function submitRecord(
        bytes32 inputHash,
        string calldata metadataURI
    ) external returns (bytes32 recordId) {
        if (bytes(metadataURI).length > 200) {
            revert("Metadata URI too long");
        }

        // Rate limiting
        SubmissionInfo storage entityInfo = submissionInfo[msg.sender];
        if (block.timestamp >= entityInfo.lastSubmissionTimestamp + SUBMISSION_WINDOW) {
            entityInfo.submissionCount = 0;
            entityInfo.lastSubmissionTimestamp = block.timestamp;
        } else {
            if (block.timestamp < entityInfo.lastSubmissionTimestamp + MIN_SUBMISSION_INTERVAL) {
                revert("Submission interval too short");
            }
            if (entityInfo.submissionCount >= MAX_SUBMISSIONS_PER_WINDOW) {
                emit RateLimitTriggered(msg.sender, block.timestamp);
                revert("Submission limit exceeded");
            }
        }

        entityInfo.submissionCount += 1;

        // Deterministic ID generation using keccak256 on inputHash, msg.sender, and block.timestamp
        recordId = keccak256(abi.encodePacked(inputHash, msg.sender, block.timestamp));

        records[recordId] = Record({
            recordId: recordId,
            creator: msg.sender,
            inputHash: inputHash,
            metadataURI: metadataURI,
            timestamp: block.timestamp,
            status: RecordStatus.Pending,
            reviewer: address(0)
        });

        emit RecordSubmitted(recordId, msg.sender, inputHash, metadataURI, block.timestamp);

        return recordId;
    }

    // Function to verify a record
    function verifyRecord(bytes32 recordId, string calldata reason) external onlyAuthorizedReviewer recordPending(recordId) {
        records[recordId].status = RecordStatus.Verified;
        records[recordId].reviewer = msg.sender;
        records[recordId].timestamp = block.timestamp;

        emit RecordProcessed(recordId, RecordStatus.Verified, msg.sender, block.timestamp, reason);
    }

    // Function to reject a record
    function rejectRecord(bytes32 recordId, string calldata reason) external onlyAuthorizedReviewer recordPending(recordId) {
        records[recordId].status = RecordStatus.Rejected;
        records[recordId].reviewer = msg.sender;
        records[recordId].timestamp = block.timestamp;

        emit RecordProcessed(recordId, RecordStatus.Rejected, msg.sender, block.timestamp, reason);
    }

    // Function to verify a record's data hash deterministically
    function verifyRecordHash(bytes32 recordId, bytes32 inputHash) external view returns (bool) {
        return records[recordId].inputHash == inputHash && records[recordId].status == RecordStatus.Verified;
    }

    // Function to get record details
    function getRecordDetails(bytes32 recordId)
        external
        view
        returns (
            address creator,
            bytes32 inputHash,
            string memory metadataURI,
            uint256 timestamp,
            RecordStatus status,
            address reviewer
        )
    {
        if (
            msg.sender != owner &&
            msg.sender != records[recordId].creator &&
            msg.sender != records[recordId].reviewer &&
            !authorizedReviewers[msg.sender]
        ) {
            revert("Not authorized to view record details");
        }

        Record memory record = records[recordId];
        return (
            record.creator,
            record.inputHash,
            record.metadataURI,
            record.timestamp,
            record.status,
            record.reviewer
        );
    }

    // Function to authorize or deauthorize a reviewer
    function setReviewerAuthorization(address reviewer, bool authorized) external onlyOwner {
        if (reviewer == address(0)) {
            revert("Reviewer address cannot be zero");
        }
        if (authorizedReviewers[reviewer] == authorized) {
            revert("Authorization status already set");
        }

        authorizedReviewers[reviewer] = authorized;
        emit ReviewerAuthorizationUpdated(reviewer, authorized, block.timestamp);
    }

    // Function to transfer ownership (simulated via authorization)
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) {
            revert("New owner cannot be zero address");
        }
        authorizedReviewers[owner] = false; // Remove old owner as authorized reviewer
        authorizedReviewers[newOwner] = true; // New owner becomes authorized
        emit ReviewerAuthorizationUpdated(newOwner, true, block.timestamp);
    }
}