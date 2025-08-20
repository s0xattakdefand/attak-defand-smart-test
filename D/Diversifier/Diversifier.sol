// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Diversifier contract for generating deterministic diversified outputs
contract Diversifier {
    // Contract owner (e.g., Agency Cryptographic Office)
    address public immutable owner;

    // Structure to store diversification request
    struct DiversificationRequest {
        bytes32 requestId; // Unique identifier for the request
        address requester; // Address of the entity requesting diversification
        bytes32 inputHash; // Hash of input data to diversify
        bytes32 diversifiedOutput; // Deterministic diversified output
        string metadataURI; // Off-chain URI for detailed metadata (e.g., IPFS link)
        uint256 timestamp; // Timestamp of request
        RequestStatus status; // Status of the request
    }

    // Struct to return request details, reducing stack usage
    struct RequestDetails {
        address requester;
        bytes32 inputHash;
        bytes32 diversifiedOutput;
        string metadataURI;
        uint256 timestamp;
        RequestStatus status;
    }

    // Enum for request status
    enum RequestStatus { Pending, Generated, Rejected }

    // Structure to store submission metadata for rate limiting
    struct SubmissionInfo {
        uint256 lastSubmissionTimestamp; // Timestamp of last submission
        uint256 submissionCount; // Number of submissions in current window
    }

    // Mapping to store diversification requests by request ID
    mapping(bytes32 => DiversificationRequest) public requests;

    // Mapping to store authorized requesters (e.g., agency officials)
    mapping(address => bool) public authorizedRequesters;

    // Mapping to store submission metadata for rate limiting
    mapping(address => SubmissionInfo) public submissionInfo;

    // Rate limit parameters to prevent DoS
    uint256 public constant SUBMISSION_WINDOW = 1 hours; // Time window for rate limiting
    uint256 public constant MAX_SUBMISSIONS_PER_WINDOW = 5; // Max submissions per window
    uint256 public constant MIN_SUBMISSION_INTERVAL = 10 seconds; // Minimum time between submissions

    // Event emitted when a diversification request is submitted
    event RequestSubmitted(
        bytes32 indexed requestId,
        address indexed requester,
        bytes32 inputHash,
        string metadataURI,
        uint256 timestamp
    );

    // Event emitted when a diversification request is processed (generated or rejected)
    event RequestProcessed(
        bytes32 indexed requestId,
        RequestStatus status,
        bytes32 diversifiedOutput,
        uint256 timestamp,
        string reason
    );

    // Event emitted when a requester is authorized or deauthorized
    event RequesterAuthorizationUpdated(address indexed requester, bool authorized, uint256 timestamp);

    // Event emitted when rate limit is triggered
    event RateLimitTriggered(address indexed entity, uint256 timestamp);

    // Modifier to restrict functions to the contract owner
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    // Modifier to restrict functions to authorized requesters
    modifier onlyAuthorizedRequester() {
        require(authorizedRequesters[msg.sender], "Only authorized requesters can call this function");
        _;
    }

    // Modifier to check if a request is pending
    modifier requestPending(bytes32 requestId) {
        require(requests[requestId].status == RequestStatus.Pending, "Request not pending or does not exist");
        _;
    }

    // Constructor to set the immutable owner
    constructor() {
        owner = msg.sender;
        authorizedRequesters[msg.sender] = true; // Owner is authorized by default
    }

    // Function to submit a diversification request with rate limiting
    function submitRequest(
        bytes32 requestId,
        bytes32 inputHash,
        string calldata metadataURI
    ) external onlyAuthorizedRequester {
        require(requests[requestId].status == RequestStatus.Pending, "Request ID already exists");
        require(bytes(metadataURI).length <= 200, "Metadata URI too long");

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
            if (entityInfo.submissionCount >= MAX_SUBMISSIONS_PER_WINDOW) {
                emit RateLimitTriggered(msg.sender, block.timestamp);
                revert("Submission limit exceeded");
            }
        }

        entityInfo.submissionCount += 1;

        requests[requestId] = DiversificationRequest({
            requestId: requestId,
            requester: msg.sender,
            inputHash: inputHash,
            diversifiedOutput: bytes32(0),
            metadataURI: metadataURI,
            timestamp: block.timestamp,
            status: RequestStatus.Pending
        });

        emit RequestSubmitted(requestId, msg.sender, inputHash, metadataURI, block.timestamp);
    }

    // Function to generate diversified output deterministically
    function generateDiversifiedOutput(bytes32 requestId, string calldata reason) external onlyAuthorizedRequester requestPending(requestId) {
        DiversificationRequest storage request = requests[requestId];

        // Deterministic diversification using keccak256 on inputHash, requester, and timestamp
        bytes32 diversifiedOutput = keccak256(abi.encodePacked(request.inputHash, request.requester, block.timestamp));

        request.diversifiedOutput = diversifiedOutput;
        request.status = RequestStatus.Generated;
        request.timestamp = block.timestamp;

        emit RequestProcessed(requestId, RequestStatus.Generated, diversifiedOutput, block.timestamp, reason);
    }

    // Function to reject a diversification request
    function rejectRequest(bytes32 requestId, string calldata reason) external onlyAuthorizedRequester requestPending(requestId) {
        requests[requestId].status = RequestStatus.Rejected;
        requests[requestId].timestamp = block.timestamp;

        emit RequestProcessed(requestId, RequestStatus.Rejected, bytes32(0), block.timestamp, reason);
    }

    // Function to verify a diversified output deterministically
    function verifyDiversifiedOutput(bytes32 requestId, bytes32 diversifiedOutput) external view returns (bool) {
        return requests[requestId].diversifiedOutput == diversifiedOutput && requests[requestId].status == RequestStatus.Generated;
    }

    // Function to get diversification request details, optimized for stack usage
    function getRequestDetails(bytes32 requestId) external view returns (RequestDetails memory) {
        require(
            msg.sender == owner ||
            msg.sender == requests[requestId].requester ||
            authorizedRequesters[msg.sender],
            "Not authorized to view request details"
        );

        DiversificationRequest storage request = requests[requestId];
        return RequestDetails({
            requester: request.requester,
            inputHash: request.inputHash,
            diversifiedOutput: request.diversifiedOutput,
            metadataURI: request.metadataURI,
            timestamp: request.timestamp,
            status: request.status
        });
    }

    // Function to authorize or deauthorize a requester
    function setRequesterAuthorization(address requester, bool authorized) external onlyOwner {
        require(requester != address(0), "Requester address cannot be zero");
        require(authorizedRequesters[requester] != authorized, "Authorization status already set");

        authorizedRequesters[requester] = authorized;
        emit RequesterAuthorizationUpdated(requester, authorized, block.timestamp);
    }

    // Function to transfer ownership
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "New owner cannot be zero address");
        authorizedRequesters[owner] = false; // Remove old owner as authorized requester
        authorizedRequesters[newOwner] = true; // New owner becomes authorized
        emit RequesterAuthorizationUpdated(newOwner, true, block.timestamp);
    }
}