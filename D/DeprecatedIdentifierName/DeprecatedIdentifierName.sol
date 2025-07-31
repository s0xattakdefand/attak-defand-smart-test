// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ModernAgencyManager contract for managing project milestones and data access using modern Solidity syntax
contract ModernAgencyManager {
    // Contract owner (e.g., Agency Program Office)
    address public owner;

    // Structure to store project milestone
    struct Milestone {
        bytes32 milestoneId; // Unique identifier for the milestone
        address submitter; // Address of the entity submitting the milestone
        string milestoneName; // Name of the milestone (e.g., Initiation, Completion)
        bytes32 dataHash; // Hash of milestone details (using keccak256, not deprecated sha3)
        string metadataURI; // Off-chain URI for detailed metadata (e.g., IPFS link)
        uint256 createdAt; // Timestamp when milestone was submitted
        uint256 updatedAt; // Timestamp of last update
        MilestoneStatus status; // Status of the milestone
        address approver; // Address of the entity approving/rejecting the milestone
    }

    // Structure to store data access request
    struct DataAccessRequest {
        bytes32 requestId; // Unique identifier for the request
        address requester; // Address of the entity requesting data access
        bytes32 dataId; // Hashed identifier for sensitive data (e.g., CUI)
        string metadataURI; // Off-chain URI for access details
        uint256 timestamp; // Timestamp of request
        AccessStatus status; // Status of the access request
        address approver; // Address of the entity approving/rejecting the request
    }

    // Enum for milestone status
    enum MilestoneStatus { Pending, Approved, Rejected, Completed }

    // Enum for data access status
    enum AccessStatus { Pending, Approved, Rejected }

    // Structure to store submission metadata for rate limiting
    struct SubmissionInfo {
        uint256 lastSubmissionTimestamp; // Timestamp of last submission
        uint256 submissionCount; // Number of submissions in current window
    }

    // Mapping to store milestones by milestone ID
    mapping(bytes32 => Milestone) public milestones;

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

    // Event emitted when a milestone is submitted
    event MilestoneSubmitted(
        bytes32 indexed milestoneId,
        address indexed submitter,
        string milestoneName,
        bytes32 dataHash,
        string metadataURI,
        uint256 timestamp
    );

    // Event emitted when a milestone is processed
    event MilestoneProcessed(
        bytes32 indexed milestoneId,
        MilestoneStatus status,
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
        if (msg.sender != owner) {
            revert("Only owner can call this function");
        }
        _;
    }

    // Modifier to restrict functions to authorized entities
    modifier onlyAuthorizedEntity() {
        if (!authorizedEntities[msg.sender]) {
            revert("Only authorized entities can call this function");
        }
        _;
    }

    // Modifier to check if a milestone is pending
    modifier milestonePending(bytes32 milestoneId) {
        if (milestones[milestoneId].status != MilestoneStatus.Pending) {
            revert("Milestone not pending or does not exist");
        }
        _;
    }

    // Modifier to check if a data access request is pending
    modifier requestPending(bytes32 requestId) {
        if (dataRequests[requestId].status != AccessStatus.Pending) {
            revert("Request not pending or does not exist");
        }
        _;
    }

    // Constructor to set the owner
    constructor() {
        owner = msg.sender;
        authorizedEntities[msg.sender] = true; // Owner is authorized by default
    }

    // Function to submit a new milestone with rate limiting
    function submitMilestone(
        bytes32 milestoneId,
        string calldata milestoneName,
        bytes32 dataHash,
        string calldata metadataURI
    ) external onlyAuthorizedEntity {
        if (milestones[milestoneId].status != MilestoneStatus.Pending) {
            revert("Milestone ID already exists");
        }
        if (bytes(milestoneName).length == 0 || bytes(milestoneName).length > 100) {
            revert("Invalid milestone name length");
        }
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

        milestones[milestoneId] = Milestone({
            milestoneId: milestoneId,
            submitter: msg.sender,
            milestoneName: milestoneName,
            dataHash: dataHash,
            metadataURI: metadataURI,
            createdAt: block.timestamp,
            updatedAt: block.timestamp,
            status: MilestoneStatus.Pending,
            approver: address(0)
        });

        emit MilestoneSubmitted(milestoneId, msg.sender, milestoneName, dataHash, metadataURI, block.timestamp);
    }

    // Function to approve a milestone
    function approveMilestone(bytes32 milestoneId) external onlyAuthorizedEntity milestonePending(milestoneId) {
        milestones[milestoneId].status = MilestoneStatus.Approved;
        milestones[milestoneId].approver = msg.sender;
        milestones[milestoneId].updatedAt = block.timestamp;

        emit MilestoneProcessed(milestoneId, MilestoneStatus.Approved, msg.sender, block.timestamp);
    }

    // Function to reject a milestone
    function rejectMilestone(bytes32 milestoneId) external onlyAuthorizedEntity milestonePending(milestoneId) {
        milestones[milestoneId].status = MilestoneStatus.Rejected;
        milestones[milestoneId].approver = msg.sender;
        milestones[milestoneId].updatedAt = block.timestamp;

        emit MilestoneProcessed(milestoneId, MilestoneStatus.Rejected, msg.sender, block.timestamp);
    }

    // Function to mark a milestone as completed
    function completeMilestone(bytes32 milestoneId) external onlyAuthorizedEntity {
        if (milestones[milestoneId].status != MilestoneStatus.Approved) {
            revert("Milestone must be approved to mark as completed");
        }
        milestones[milestoneId].status = MilestoneStatus.Completed;
        milestones[milestoneId].updatedAt = block.timestamp;

        emit MilestoneProcessed(milestoneId, MilestoneStatus.Completed, msg.sender, block.timestamp);
    }

    // Function to submit a data access request
    function submitDataAccessRequest(
        bytes32 requestId,
        bytes32 dataId,
        string calldata metadataURI
    ) external onlyAuthorizedEntity {
        if (dataRequests[requestId].status != AccessStatus.Pending) {
            revert("Request ID already exists");
        }
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

    // Function to verify a milestone's data hash
    function verifyMilestoneHash(bytes32 milestoneId, bytes32 dataHash) external view returns (bool) {
        return milestones[milestoneId].dataHash == dataHash && milestones[milestoneId].status != MilestoneStatus.Rejected;
    }

    // Function to verify a data access request's data ID hash
    function verifyDataHash(bytes32 requestId, bytes32 dataId) external view returns (bool) {
        return dataRequests[requestId].dataId == dataId && dataRequests[requestId].status != AccessStatus.Rejected;
    }

    // Function to get milestone details
    function getMilestoneDetails(bytes32 milestoneId)
        external
        view
        returns (
            address submitter,
            string memory milestoneName,
            bytes32 dataHash,
            string memory metadataURI,
            uint256 createdAt,
            uint256 updatedAt,
            MilestoneStatus status,
            address approver
        )
    {
        if (
            msg.sender != owner &&
            msg.sender != milestones[milestoneId].submitter &&
            msg.sender != milestones[milestoneId].approver &&
            !authorizedEntities[msg.sender]
        ) {
            revert("Not authorized to view milestone details");
        }

        Milestone memory milestone = milestones[milestoneId];
        return (
            milestone.submitter,
            milestone.milestoneName,
            milestone.dataHash,
            milestone.metadataURI,
            milestone.createdAt,
            milestone.updatedAt,
            milestone.status,
            milestone.approver
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
        if (
            msg.sender != owner &&
            msg.sender != dataRequests[requestId].requester &&
            msg.sender != dataRequests[requestId].approver &&
            !authorizedEntities[msg.sender]
        ) {
            revert("Not authorized to view request details");
        }

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
        if (entity == address(0)) {
            revert("Entity address cannot be zero");
        }
        if (authorizedEntities[entity] == authorized) {
            revert("Authorization status already set");
        }

        authorizedEntities[entity] = authorized;
        emit EntityAuthorizationUpdated(entity, authorized, block.timestamp);
    }

    // Function to transfer ownership
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) {
            revert("New owner cannot be zero address");
        }
        authorizedEntities[owner] = false; // Remove old owner as authorized entity
        owner = newOwner;
        authorizedEntities[newOwner] = true; // New owner becomes authorized
        emit EntityAuthorizationUpdated(newOwner, true, block.timestamp);
    }
}