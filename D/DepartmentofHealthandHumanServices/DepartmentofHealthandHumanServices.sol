// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// HHSClaimsAndData contract for managing Department of Health and Human Services claims and patient data access
contract HHSClaimsAndData {
    // Contract owner (e.g., HHS Office of the Secretary)
    address public owner;

    // Structure to store claim submission
    struct Claim {
        bytes32 claimId; // Unique identifier for the claim
        address provider; // Address of the healthcare provider submitting the claim
        address insurer; // Address of the insurer processing the claim
        uint256 amount; // Claim amount (in USD, scaled to wei)
        bytes32 dataHash; // Hash of claim data (e.g., procedure details)
        string metadataURI; // Off-chain URI for detailed metadata (e.g., IPFS link)
        uint256 createdAt; // Timestamp when claim was created
        uint256 updatedAt; // Timestamp of last update
        ClaimStatus status; // Status of the claim
    }

    // Structure to store patient data access request
    struct DataAccessRequest {
        bytes32 requestId; // Unique identifier for the request
        address requester; // Address of the entity requesting data access
        bytes32 patientId; // Hashed patient ID (to protect PII)
        string metadataURI; // Off-chain URI for access details
        uint256 timestamp; // Timestamp of request
        AccessStatus status; // Status of the access request
        address approver; // Address of the entity approving/rejecting the request
    }

    // Enum for claim status
    enum ClaimStatus { Pending, Approved, Rejected }

    // Enum for data access status
    enum AccessStatus { Pending, Approved, Rejected }

    // Structure to store submission metadata for rate limiting
    struct SubmissionInfo {
        uint256 lastSubmissionTimestamp; // Timestamp of last submission
        uint256 submissionCount; // Number of submissions in current window
    }

    // Mapping to store claims by claim ID
    mapping(bytes32 => Claim) public claims;

    // Mapping to store data access requests by request ID
    mapping(bytes32 => DataAccessRequest) public dataAccessRequests;

    // Mapping to store authorized entities (e.g., providers, insurers)
    mapping(address => bool) public authorizedEntities;

    // Mapping to store submission metadata for rate limiting
    mapping(address => SubmissionInfo) public submissionInfo;

    // Rate limit parameters to prevent DoS
    uint256 public constant SUBMISSION_WINDOW = 1 hours; // Time window for rate limiting
    uint256 public constant MAX_SUBMISSIONS_PER_WINDOW = 5; // Max submissions per window
    uint256 public constant MIN_SUBMISSION_INTERVAL = 10 seconds; // Minimum time between submissions

    // ERC-20 token for claim payments (e.g., representing USD or stablecoin)
    address public paymentToken;

    // Event emitted when a claim is submitted
    event ClaimSubmitted(
        bytes32 indexed claimId,
        address indexed provider,
        address indexed insurer,
        uint256 amount,
        bytes32 dataHash,
        string metadataURI,
        uint256 timestamp
    );

    // Event emitted when a claim is processed
    event ClaimProcessed(bytes32 indexed claimId, ClaimStatus status, uint256 timestamp);

    // Event emitted when a data access request is submitted
    event DataAccessRequested(bytes32 indexed requestId, address indexed requester, bytes32 patientId, string metadataURI, uint256 timestamp);

    // Event emitted when a data access request is processed
    event DataAccessProcessed(bytes32 indexed requestId, AccessStatus status, address indexed approver, uint256 timestamp);

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

    // Modifier to check if a claim is pending
    modifier claimPending(bytes32 claimId) {
        require(claims[claimId].status == ClaimStatus.Pending, "Claim not pending or does not exist");
        _;
    }

    // Modifier to check if a data access request is pending
    modifier requestPending(bytes32 requestId) {
        require(dataAccessRequests[requestId].status == AccessStatus.Pending, "Request not pending or does not exist");
        _;
    }

    // Constructor to set the owner and payment token address
    constructor(address _paymentToken) {
        require(_paymentToken != address(0), "Payment token address cannot be zero");
        owner = msg.sender;
        paymentToken = _paymentToken;
        authorizedEntities[msg.sender] = true; // Owner is authorized by default
    }

    // Function to submit a new claim with rate limiting
    function submitClaim(
        bytes32 claimId,
        address insurer,
        uint256 amount,
        bytes32 dataHash,
        string calldata metadataURI
    ) external onlyAuthorizedEntity {
        require(claims[claimId].status == ClaimStatus.Pending, "Claim ID already exists");
        require(insurer != address(0), "Insurer address cannot be zero");
        require(amount > 0, "Claim amount must be greater than zero");
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

        claims[claimId] = Claim({
            claimId: claimId,
            provider: msg.sender,
            insurer: insurer,
            amount: amount,
            dataHash: dataHash,
            metadataURI: metadataURI,
            createdAt: block.timestamp,
            updatedAt: block.timestamp,
            status: ClaimStatus.Pending
        });

        emit ClaimSubmitted(claimId, msg.sender, insurer, amount, dataHash, metadataURI, block.timestamp);
    }

    // Function to approve a claim and process payment
    function approveClaim(bytes32 claimId) external onlyAuthorizedEntity claimPending(claimId) {
        Claim storage claim = claims[claimId];
        require(msg.sender == claim.insurer, "Only insurer can approve claim");

        // Transfer payment tokens from insurer to provider
        require(IERC20(paymentToken).transferFrom(msg.sender, claim.provider, claim.amount), "Payment transfer failed");

        claim.status = ClaimStatus.Approved;
        claim.updatedAt = block.timestamp;

        emit ClaimProcessed(claimId, ClaimStatus.Approved, block.timestamp);
    }

    // Function to reject a claim
    function rejectClaim(bytes32 claimId) external onlyAuthorizedEntity claimPending(claimId) {
        Claim storage claim = claims[claimId];
        require(msg.sender == claim.insurer, "Only insurer can reject claim");

        claim.status = ClaimStatus.Rejected;
        claim.updatedAt = block.timestamp;

        emit ClaimProcessed(claimId, ClaimStatus.Rejected, block.timestamp);
    }

    // Function to submit a data access request
    function submitDataAccessRequest(bytes32 requestId, bytes32 patientId, string calldata metadataURI)
        external
        onlyAuthorizedEntity
    {
        require(dataAccessRequests[requestId].status == AccessStatus.Pending, "Request ID already exists");
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

        dataAccessRequests[requestId] = DataAccessRequest({
            requestId: requestId,
            requester: msg.sender,
            patientId: patientId,
            metadataURI: metadataURI,
            timestamp: block.timestamp,
            status: AccessStatus.Pending,
            approver: address(0)
        });

        emit DataAccessRequested(requestId, msg.sender, patientId, metadataURI, block.timestamp);
    }

    // Function to approve a data access request
    function approveDataAccess(bytes32 requestId) external onlyAuthorizedEntity requestPending(requestId) {
        DataAccessRequest storage request = dataAccessRequests[requestId];
        request.status = AccessStatus.Approved;
        request.approver = msg.sender;
        request.timestamp = block.timestamp;

        emit DataAccessProcessed(requestId, AccessStatus.Approved, msg.sender, block.timestamp);
    }

    // Function to reject a data access request
    function rejectDataAccess(bytes32 requestId) external onlyAuthorizedEntity requestPending(requestId) {
        DataAccessRequest storage request = dataAccessRequests[requestId];
        request.status = AccessStatus.Rejected;
        request.approver = msg.sender;
        request.timestamp = block.timestamp;

        emit DataAccessProcessed(requestId, AccessStatus.Rejected, msg.sender, block.timestamp);
    }

    // Function to verify a claim's data hash
    function verifyClaimHash(bytes32 claimId, bytes32 dataHash) external view returns (bool) {
        return claims[claimId].dataHash == dataHash && claims[claimId].status != ClaimStatus.Rejected;
    }

    // Function to get claim details
    function getClaimDetails(bytes32 claimId)
        external
        view
        returns (
            address provider,
            address insurer,
            uint256 amount,
            bytes32 dataHash,
            string memory metadataURI,
            uint256 createdAt,
            uint256 updatedAt,
            ClaimStatus status
        )
    {
        require(
            msg.sender == owner ||
            msg.sender == claims[claimId].provider ||
            msg.sender == claims[claimId].insurer ||
            authorizedEntities[msg.sender],
            "Not authorized to view claim details"
        );

        Claim memory claim = claims[claimId];
        return (
            claim.provider,
            claim.insurer,
            claim.amount,
            claim.dataHash,
            claim.metadataURI,
            claim.createdAt,
            claim.updatedAt,
            claim.status
        );
    }

    // Function to get data access request details
    function getDataAccessDetails(bytes32 requestId)
        external
        view
        returns (
            address requester,
            bytes32 patientId,
            string memory metadataURI,
            uint256 timestamp,
            AccessStatus status,
            address approver
        )
    {
        require(
            msg.sender == owner ||
            msg.sender == dataAccessRequests[requestId].requester ||
            authorizedEntities[msg.sender],
            "Not authorized to view request details"
        );

        DataAccessRequest memory request = dataAccessRequests[requestId];
        return (
            request.requester,
            request.patientId,
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

// Interface for ERC-20 token interactions
interface IERC20 {
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
}