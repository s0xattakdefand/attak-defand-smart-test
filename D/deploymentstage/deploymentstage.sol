// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// DeploymentStageManager contract for managing deployment stages and data access
contract DeploymentStageManager {
    // Contract owner (e.g., Agency Program Office)
    address public owner;

    // Structure to store deployment stage
    struct DeploymentStage {
        bytes32 stageId; // Unique identifier for the deployment stage
        address submitter; // Address of the entity submitting the stage update
        string stageName; // Name of the stage (e.g., Planning, Execution, Monitoring)
        bytes32 dataHash; // Hash of stage details (e.g., project plan, resource allocation)
        string metadataURI; // Off-chain URI for detailed metadata (e.g., IPFS link)
        uint256 createdAt; // Timestamp when stage was submitted
        uint256 updatedAt; // Timestamp of last update
        StageStatus status; // Status of the stage
        address approver; // Address of the entity approving/rejecting the stage
    }

    // Structure to store data access request
    struct DataAccessRequest {
        bytes32 requestId; // Unique identifier for the request
        address requester; // Address of the entity requesting data access
        bytes32 dataId; // Hashed identifier for deployment-related data
        string metadataURI; // Off-chain URI for access details
        uint256 timestamp; // Timestamp of request
        AccessStatus status; // Status of the access request
        address approver; // Address of the entity approving/rejecting the request
    }

    // Enum for deployment stage status
    enum StageStatus { Pending, Approved, Rejected, Completed }

    // Enum for data access status
    enum AccessStatus { Pending, Approved, Rejected }

    // Structure to store submission metadata for rate limiting
    struct SubmissionInfo {
        uint256 lastSubmissionTimestamp; // Timestamp of last submission
        uint256 submissionCount; // Number of submissions in current window
    }

    // Mapping to store deployment stages by stage ID
    mapping(bytes32 => DeploymentStage) public stages;

    // Mapping to store data access requests by request ID
    mapping(bytes32 => DataAccessRequest) public dataRequests;

    // Mapping to store authorized entities (e.g., program managers, data stewards)
    mapping(address => bool) public authorizedEntities;

    // Mapping to store submission metadata for rate limiting
    mapping(address => SubmissionInfo) public submissionInfo;

    // Rate limit parameters to prevent DoS
    uint256 public constant SUBMISSION_WINDOW = 1 hours; // Time window for rate limiting
    uint256 public constant MAX_SUBMISSIONS_PER_WINDOW = 5; // Max submissions per window
    uint256 public constant MIN_SUBMISSION_INTERVAL = 10 seconds; // Minimum time between submissions

    // Event emitted when a deployment stage is submitted
    event StageSubmitted(
        bytes32 indexed stageId,
        address indexed submitter,
        string stageName,
        bytes32 dataHash,
        string metadataURI,
        uint256 timestamp
    );

    // Event emitted when a deployment stage is processed
    event StageProcessed(
        bytes32 indexed stageId,
        StageStatus status,
        address indexed approver,
        uint256 timestamp
    );

    // Event emitted when a data access request is submitted
    event DataAccessRequested(
        bytes32 indexed requestId,
        address indexed requester,
        bytes32 dataId,
        string metadataURI,
        uint256 timestamp
    );

    // Event emitted when a data access request is processed
    event DataAccessProcessed(
        bytes32 indexed requestId,
        AccessStatus status,
        address indexed approver,
        uint256 timestamp
    );

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

    // Modifier to check if a deployment stage is pending
    modifier stagePending(bytes32 stageId) {
        require(stages[stageId].status == StageStatus.Pending, "Stage not pending or does not exist");
        _;
    }

    // Modifier to check if a data access request is pending
    modifier requestPending(bytes32 requestId) {
        require(dataRequests[requestId].status == AccessStatus.Pending, "Request not pending or does not exist");
        _;
    }

    // Constructor to set the owner
    constructor() {
        owner = msg.sender;
        authorizedEntities[msg.sender] = true; // Owner is authorized by default
    }

    // Function to submit a new deployment stage with rate limiting
    function submitStage(
        bytes32 stageId,
        string calldata stageName,
        bytes32 dataHash,
        string calldata metadataURI
    ) external onlyAuthorizedEntity {
        require(stages[stageId].status == StageStatus.Pending, "Stage ID already exists");
        require(bytes(stageName).length > 0 && bytes(stageName).length <= 100, "Invalid stage name length");
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

        stages[stageId] = DeploymentStage({
            stageId: stageId,
            submitter: msg.sender,
            stageName: stageName,
            dataHash: dataHash,
            metadataURI: metadataURI,
            createdAt: block.timestamp,
            updatedAt: block.timestamp,
            status: StageStatus.Pending,
            approver: address(0)
        });

        emit StageSubmitted(stageId, msg.sender, stageName, dataHash, metadataURI, block.timestamp);
    }

    // Function to approve a deployment stage
    function approveStage(bytes32 stageId) external onlyAuthorizedEntity stagePending(stageId) {
        stages[stageId].status = StageStatus.Approved;
        stages[stageId].approver = msg.sender;
        stages[stageId].updatedAt = block.timestamp;

        emit StageProcessed(stageId, StageStatus.Approved, msg.sender, block.timestamp);
    }

    // Function to reject a deployment stage
    function rejectStage(bytes32 stageId) external onlyAuthorizedEntity stagePending(stageId) {
        stages[stageId].status = StageStatus.Rejected;
        stages[stageId].approver = msg.sender;
        stages[stageId].updatedAt = block.timestamp;

        emit StageProcessed(stageId, StageStatus.Rejected, msg.sender, block.timestamp);
    }

    // Function to mark a deployment stage as completed
    function completeStage(bytes32 stageId) external onlyAuthorizedEntity {
        require(
            stages[stageId].status == StageStatus.Approved,
            "Stage must be approved to mark as completed"
        );
        stages[stageId].status = StageStatus.Completed;
        stages[stageId].updatedAt = block.timestamp;

        emit StageProcessed(stageId, StageStatus.Completed, msg.sender, block.timestamp);
    }

    // Function to submit a data access request
    function submitDataAccessRequest(
        bytes32 requestId,
        bytes32 dataId,
        string calldata metadataURI
    ) external onlyAuthorizedEntity {
        require(dataRequests[requestId].status == AccessStatus.Pending, "Request ID already exists");
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

        dataRequests[requestId] = DataAccessRequest({
            requestId: requestId,
            requester: msg.sender,
            dataId: dataId,
            metadataURI: metadataURI,
            timestamp: block.timestamp,
            status: AccessStatus.Pending,
            approver: address(0)
        });

        emit DataAccessRequested(requestId, msg.sender, dataId, metadataURI, block.timestamp);
    }

    // Function to approve a data access request
    function approveDataAccess(bytes32 requestId) external onlyAuthorizedEntity requestPending(requestId) {
        dataRequests[requestId].status = AccessStatus.Approved;
        dataRequests[requestId].approver = msg.sender;
        dataRequests[requestId].timestamp = block.timestamp;

        emit DataAccessProcessed(requestId, AccessStatus.Approved, msg.sender, block.timestamp);
    }

    // Function to reject a data access request
    function rejectDataAccess(bytes32 requestId) external onlyAuthorizedEntity requestPending(requestId) {
        dataRequests[requestId].status = AccessStatus.Rejected;
        dataRequests[requestId].approver = msg.sender;
        dataRequests[requestId].timestamp = block.timestamp;

        emit DataAccessProcessed(requestId, AccessStatus.Rejected, msg.sender, block.timestamp);
    }

    // Function to verify a deployment stage's data hash
    function verifyStageHash(bytes32 stageId, bytes32 dataHash) external view returns (bool) {
        return stages[stageId].dataHash == dataHash && stages[stageId].status != StageStatus.Rejected;
    }

    // Function to verify a data access request's data ID hash
    function verifyDataHash(bytes32 requestId, bytes32 dataId) external view returns (bool) {
        return dataRequests[requestId].dataId == dataId && dataRequests[requestId].status != AccessStatus.Rejected;
    }

    // Function to get deployment stage details
    function getStageDetails(bytes32 stageId)
        external
        view
        returns (
            address submitter,
            string memory stageName,
            bytes32 dataHash,
            string memory metadataURI,
            uint256 createdAt,
            uint256 updatedAt,
            StageStatus status,
            address approver
        )
    {
        require(
            msg.sender == owner ||
            msg.sender == stages[stageId].submitter ||
            msg.sender == stages[stageId].approver ||
            authorizedEntities[msg.sender],
            "Not authorized to view stage details"
        );

        DeploymentStage memory stage = stages[stageId];
        return (
            stage.submitter,
            stage.stageName,
            stage.dataHash,
            stage.metadataURI,
            stage.createdAt,
            stage.updatedAt,
            stage.status,
            stage.approver
        );
    }

    // Function to get data access request details
    function getDataAccessDetails(bytes32 requestId)
        external
        view
        returns (
            address requester,
            bytes32 dataId,
            string memory metadataURI,
            uint256 timestamp,
            AccessStatus status,
            address approver
        )
    {
        require(
            msg.sender == owner ||
            msg.sender == dataRequests[requestId].requester ||
            msg.sender == dataRequests[requestId].approver ||
            authorizedEntities[msg.sender],
            "Not authorized to view request details"
        );

        DataAccessRequest memory request = dataRequests[requestId];
        return (
            request.requester,
            request.dataId,
            request.metadataURI,
            request.timestamp,
            request.status,
            request.approver
        );
    }

    // Function to authorize or deauthorize an entity
    function setEntityAuthorization(address entity, bool authorized) external onlyOwner {
        require(entity != address(0), "Entity address cannot be zero");
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