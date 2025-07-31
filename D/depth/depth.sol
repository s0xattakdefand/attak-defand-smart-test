// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// DepthProjectManager contract for managing hierarchical project phases and data access
contract DepthProjectManager {
    // Contract owner (e.g., Agency Program Office)
    address public owner;

    // Structure to store project phase (milestone or task with depth)
    struct ProjectPhase {
        bytes32 phaseId; // Unique identifier for the phase
        bytes32 parentPhaseId; // ID of parent phase (0x0 for root phases)
        address submitter; // Address of the entity submitting the phase
        string phaseName; // Name of the phase (e.g., Planning, Subtask 1)
        bytes32 dataHash; // Hash of phase details (using keccak256)
        string metadataURI; // Off-chain URI for detailed metadata (e.g., IPFS link)
        uint256 createdAt; // Timestamp when phase was submitted
        uint256 updatedAt; // Timestamp of last update
        PhaseStatus status; // Status of the phase
        address approver; // Address of the entity approving/rejecting the phase
    }

    // Structure to store data access request
    struct DataAccessRequest {
        bytes32 requestId; // Unique identifier for the request
        address requester; // Address of the entity requesting data access
        bytes32 dataId; // Hashed identifier for sensitive data (e.g., CUI)
        uint256 accessLevel; // Access level required (e.g., 1 for basic, higher for restricted)
        string metadataURI; // Off-chain URI for access details
        uint256 timestamp; // Timestamp of request
        AccessStatus status; // Status of the access request
        address approver; // Address of the entity approving/rejecting the request
    }

    // Enum for phase status
    enum PhaseStatus { Pending, Approved, Rejected, Completed }

    // Enum for data access status
    enum AccessStatus { Pending, Approved, Rejected }

    // Structure to store submission metadata for rate limiting
    struct SubmissionInfo {
        uint256 lastSubmissionTimestamp; // Timestamp of last submission
        uint256 submissionCount; // Number of submissions in current window
    }

    // Mapping to store project phases by phase ID
    mapping(bytes32 => ProjectPhase) public phases;

    // Mapping to store data access requests by request ID
    mapping(bytes32 => DataAccessRequest) public dataRequests;

    // Mapping to store authorized entities and their access level
    mapping(address => uint256) public authorizedEntities; // 0 = unauthorized, >0 = access level

    // Mapping to store submission metadata for rate limiting
    mapping(address => SubmissionInfo) public submissionInfo;

    // Rate limit parameters to prevent DoS
    uint256 public constant SUBMISSION_WINDOW = 1 hours; // Time window for rate limiting
    uint256 public constant MAX_SUBMISSIONS_PER_WINDOW = 5; // Max submissions per window
    uint256 public constant MIN_SUBMISSION_INTERVAL = 10 seconds; // Minimum time between submissions

    // Maximum access level for data requests
    uint256 public constant MAX_ACCESS_LEVEL = 5; // Defines depth of access hierarchy

    // Event emitted when a project phase is submitted
    event PhaseSubmitted(
        bytes32 indexed phaseId,
        bytes32 indexed parentPhaseId,
        address indexed submitter,
        string phaseName,
        bytes32 dataHash,
        string metadataURI,
        uint256 timestamp
    );

    // Event emitted when a project phase is processed
    event PhaseProcessed(
        bytes32 indexed phaseId,
        PhaseStatus status,
        address indexed approver,
        uint256 timestamp
    );

    // Event emitted when a data access request is submitted
    event DataAccessRequested(
        bytes32 indexed requestId,
        address indexed requester,
        bytes32 dataId,
        uint256 accessLevel,
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
    event EntityAuthorizationUpdated(address indexed entity, uint256 accessLevel, uint256 timestamp);

    // Event emitted when rate limit is triggered
    event RateLimitTriggered(address indexed entity, uint256 timestamp);

    // Modifier to restrict functions to the contract owner
    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert("Only owner can call this function");
        }
        _;
    }

    // Modifier to restrict functions to authorized entities with sufficient access level
    modifier onlyAuthorizedEntity(uint256 requiredLevel) {
        if (authorizedEntities[msg.sender] < requiredLevel) {
            revert("Insufficient access level or unauthorized");
        }
        _;
    }

    // Modifier to check if a phase is pending
    modifier phasePending(bytes32 phaseId) {
        if (phases[phaseId].status != PhaseStatus.Pending) {
            revert("Phase not pending or does not exist");
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
        authorizedEntities[msg.sender] = MAX_ACCESS_LEVEL; // Owner has maximum access level
    }

    // Function to submit a new project phase with rate limiting
    function submitPhase(
        bytes32 phaseId,
        bytes32 parentPhaseId,
        string calldata phaseName,
        bytes32 dataHash,
        string calldata metadataURI
    ) external onlyAuthorizedEntity(1) {
        if (phases[phaseId].status != PhaseStatus.Pending) {
            revert("Phase ID already exists");
        }
        if (parentPhaseId != bytes32(0) && phases[parentPhaseId].status != PhaseStatus.Approved) {
            revert("Parent phase must be approved or nonexistent");
        }
        if (bytes(phaseName).length == 0 || bytes(phaseName).length > 100) {
            revert("Invalid phase name length");
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

        phases[phaseId] = ProjectPhase({
            phaseId: phaseId,
            parentPhaseId: parentPhaseId,
            submitter: msg.sender,
            phaseName: phaseName,
            dataHash: dataHash,
            metadataURI: metadataURI,
            createdAt: block.timestamp,
            updatedAt: block.timestamp,
            status: PhaseStatus.Pending,
            approver: address(0)
        });

        emit PhaseSubmitted(phaseId, parentPhaseId, msg.sender, phaseName, dataHash, metadataURI, block.timestamp);
    }

    // Function to approve a project phase
    function approvePhase(bytes32 phaseId) external onlyAuthorizedEntity(2) phasePending(phaseId) {
        phases[phaseId].status = PhaseStatus.Approved;
        phases[phaseId].approver = msg.sender;
        phases[phaseId].updatedAt = block.timestamp;

        emit PhaseProcessed(phaseId, PhaseStatus.Approved, msg.sender, block.timestamp);
    }

    // Function to reject a project phase
    function rejectPhase(bytes32 phaseId) external onlyAuthorizedEntity(2) phasePending(phaseId) {
        phases[phaseId].status = PhaseStatus.Rejected;
        phases[phaseId].approver = msg.sender;
        phases[phaseId].updatedAt = block.timestamp;

        emit PhaseProcessed(phaseId, PhaseStatus.Rejected, msg.sender, block.timestamp);
    }

    // Function to mark a project phase as completed
    function completePhase(bytes32 phaseId) external onlyAuthorizedEntity(2) {
        if (phases[phaseId].status != PhaseStatus.Approved) {
            revert("Phase must be approved to mark as completed");
        }
        phases[phaseId].status = PhaseStatus.Completed;
        phases[phaseId].updatedAt = block.timestamp;

        emit PhaseProcessed(phaseId, PhaseStatus.Completed, msg.sender, block.timestamp);
    }

    // Function to submit a data access request
    function submitDataAccessRequest(
        bytes32 requestId,
        bytes32 dataId,
        uint256 accessLevel,
        string calldata metadataURI
    ) external onlyAuthorizedEntity(accessLevel) {
        if (dataRequests[requestId].status != AccessStatus.Pending) {
            revert("Request ID already exists");
        }
        if (accessLevel == 0 || accessLevel > MAX_ACCESS_LEVEL) {
            revert("Invalid access level");
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
            accessLevel: accessLevel,
            metadataURI: metadataURI,
            timestamp: block.timestamp,
            status: AccessStatus.Pending,
            approver: address(0)
        });

        emit DataAccessRequested(requestId, msg.sender, dataId, accessLevel, metadataURI, block.timestamp);
    }

    // Function to approve a data access request
    function approveDataAccess(bytes32 requestId) external onlyAuthorizedEntity(dataRequests[requestId].accessLevel) requestPending(requestId) {
        dataRequests[requestId].status = AccessStatus.Approved;
        dataRequests[requestId].approver = msg.sender;
        dataRequests[requestId].timestamp = block.timestamp;

        emit DataAccessProcessed(requestId, AccessStatus.Approved, msg.sender, block.timestamp);
    }

    // Function to reject a data access request
    function rejectDataAccess(bytes32 requestId) external onlyAuthorizedEntity(dataRequests[requestId].accessLevel) requestPending(requestId) {
        dataRequests[requestId].status = AccessStatus.Rejected;
        dataRequests[requestId].approver = msg.sender;
        dataRequests[requestId].timestamp = block.timestamp;

        emit DataAccessProcessed(requestId, AccessStatus.Rejected, msg.sender, block.timestamp);
    }

    // Function to verify a phase's data hash
    function verifyPhaseHash(bytes32 phaseId, bytes32 dataHash) external view returns (bool) {
        return phases[phaseId].dataHash == dataHash && phases[phaseId].status != PhaseStatus.Rejected;
    }

    // Function to verify a data access request's data ID hash
    function verifyDataHash(bytes32 requestId, bytes32 dataId) external view returns (bool) {
        return dataRequests[requestId].dataId == dataId && dataRequests[requestId].status != AccessStatus.Rejected;
    }

    // Function to get project phase details
    function getPhaseDetails(bytes32 phaseId)
        external
        view
        returns (
            bytes32 parentPhaseId,
            address submitter,
            string memory phaseName,
            bytes32 dataHash,
            string memory metadataURI,
            uint256 createdAt,
            uint256 updatedAt,
            PhaseStatus status,
            address approver
        )
    {
        if (
            msg.sender != owner &&
            msg.sender != phases[phaseId].submitter &&
            msg.sender != phases[phaseId].approver &&
            authorizedEntities[msg.sender] == 0
        ) {
            revert("Not authorized to view phase details");
        }

        ProjectPhase memory phase = phases[phaseId];
        return (
            phase.parentPhaseId,
            phase.submitter,
            phase.phaseName,
            phase.dataHash,
            phase.metadataURI,
            phase.createdAt,
            phase.updatedAt,
            phase.status,
            phase.approver
        );
    }

    // Function to get data access request details
    function getDataAccessDetails(bytes32 requestId)
        external
        view
        returns (
            address requester,
            bytes32 dataId,
            uint256 accessLevel,
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
            authorizedEntities[msg.sender] < dataRequests[requestId].accessLevel
        ) {
            revert("Not authorized to view request details");
        }

        DataAccessRequest memory request = dataRequests[requestId];
        return (
            request.requester,
            request.dataId,
            request.accessLevel,
            request.metadataURI,
            request.timestamp,
            request.status,
            request.approver
        );
    }

    // Function to authorize or deauthorize an entity with an access level
    function setEntityAuthorization(address entity, uint256 accessLevel) external onlyOwner {
        if (entity == address(0)) {
            revert("Entity address cannot be zero");
        }
        if (accessLevel > MAX_ACCESS_LEVEL) {
            revert("Access level exceeds maximum");
        }
        if (authorizedEntities[entity] == accessLevel) {
            revert("Access level already set");
        }

        authorizedEntities[entity] = accessLevel;
        emit EntityAuthorizationUpdated(entity, accessLevel, block.timestamp);
    }

    // Function to transfer ownership
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) {
            revert("New owner cannot be zero address");
        }
        authorizedEntities[owner] = 0; // Remove old owner’s access level
        owner = newOwner;
        authorizedEntities[newOwner] = MAX_ACCESS_LEVEL; // New owner gets maximum access
        emit EntityAuthorizationUpdated(newOwner, MAX_ACCESS_LEVEL, block.timestamp);
    }
}