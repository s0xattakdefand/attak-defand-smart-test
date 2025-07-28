// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// DeoxyribonucleicAcid contract for managing DNA sequence metadata
contract DeoxyribonucleicAcid {
    // Contract owner (e.g., research institution or medical authority)
    address public owner;

    // Structure to store DNA sequence metadata
    struct DNASequence {
        bytes32 sequenceId; // Unique identifier for the DNA sequence
        address creator; // Address of the entity registering the sequence
        bytes32 sequenceHash; // Hash of the DNA sequence data (e.g., ACGT string)
        string metadataURI; // Off-chain URI for detailed metadata (e.g., IPFS link)
        uint256 createdAt; // Timestamp when sequence was registered
        uint256 updatedAt; // Timestamp of last update
        bool exists; // Flag to check if sequence exists
    }

    // Structure to store user submission metadata for rate limiting
    struct SubmissionInfo {
        uint256 lastSubmissionTimestamp; // Timestamp of last submission
        uint256 submissionCount; // Number of submissions in current window
    }

    // Mapping to store DNA sequences by sequence ID
    mapping(bytes32 => DNASequence) public sequences;

    // Mapping to store authorized researchers
    mapping(address => bool) public researchers;

    // Mapping to store submission metadata for rate limiting
    mapping(address => SubmissionInfo) public submissionInfo;

    // Rate limit parameters to prevent DoS
    uint256 public constant SUBMISSION_WINDOW = 1 hours; // Time window for rate limiting
    uint256 public constant MAX_SUBMISSIONS_PER_WINDOW = 5; // Max submissions per window
    uint256 public constant MIN_SUBMISSION_INTERVAL = 10 seconds; // Minimum time between submissions

    // Event emitted when a DNA sequence is registered
    event SequenceRegistered(bytes32 indexed sequenceId, address indexed creator, bytes32 sequenceHash, string metadataURI, uint256 timestamp);

    // Event emitted when a DNA sequence is updated
    event SequenceUpdated(bytes32 indexed sequenceId, bytes32 newSequenceHash, string newMetadataURI, uint256 timestamp);

    // Event emitted when a researcher is authorized or deauthorized
    event ResearcherAuthorizationUpdated(address indexed researcher, bool authorized, uint256 timestamp);

    // Event emitted when rate limit is triggered
    event RateLimitTriggered(address indexed user, uint256 timestamp);

    // Modifier to restrict functions to the contract owner
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    // Modifier to restrict functions to authorized researchers
    modifier onlyResearcher() {
        require(researchers[msg.sender], "Only authorized researchers can call this function");
        _;
    }

    // Modifier to check if a sequence exists
    modifier sequenceExists(bytes32 sequenceId) {
        require(sequences[sequenceId].exists, "Sequence does not exist");
        _;
    }

    // Constructor to set the owner
    constructor() {
        owner = msg.sender;
        researchers[msg.sender] = true; // Owner is a researcher by default
    }

    // Function to register a new DNA sequence with rate limiting
    function registerSequence(bytes32 sequenceId, bytes32 sequenceHash, string calldata metadataURI) external {
        require(!sequences[sequenceId].exists, "Sequence ID already exists");
        require(bytes(metadataURI).length <= 200, "Metadata URI too long"); // Bound input size

        // Rate limiting
        SubmissionInfo storage userInfo = submissionInfo[msg.sender];
        if (block.timestamp >= userInfo.lastSubmissionTimestamp + SUBMISSION_WINDOW) {
            userInfo.submissionCount = 0;
            userInfo.lastSubmissionTimestamp = block.timestamp;
        } else {
            require(
                block.timestamp >= userInfo.lastSubmissionTimestamp + MIN_SUBMISSION_INTERVAL,
                "Submission interval too short"
            );
            require(userInfo.submissionCount < MAX_SUBMISSIONS_PER_WINDOW, "Submission limit exceeded");
            emit RateLimitTriggered(msg.sender, block.timestamp);
        }

        userInfo.submissionCount += 1;

        sequences[sequenceId] = DNASequence({
            sequenceId: sequenceId,
            creator: msg.sender,
            sequenceHash: sequenceHash,
            metadataURI: metadataURI,
            createdAt: block.timestamp,
            updatedAt: block.timestamp,
            exists: true
        });

        emit SequenceRegistered(sequenceId, msg.sender, sequenceHash, metadataURI, block.timestamp);
    }

    // Function to update a DNA sequence
    function updateSequence(bytes32 sequenceId, bytes32 newSequenceHash, string calldata newMetadataURI)
        external
        onlyResearcher
        sequenceExists(sequenceId)
    {
        require(bytes(newMetadataURI).length <= 200, "Metadata URI too long");
        require(sequences[sequenceId].creator == msg.sender || researchers[msg.sender], "Not authorized to update");

        sequences[sequenceId].sequenceHash = newSequenceHash;
        sequences[sequenceId].metadataURI = newMetadataURI;
        sequences[sequenceId].updatedAt = block.timestamp;

        emit SequenceUpdated(sequenceId, newSequenceHash, newMetadataURI, block.timestamp);
    }

    // Function to verify a DNA sequence hash
    function verifySequenceHash(bytes32 sequenceId, bytes32 sequenceHash)
        external
        view
        sequenceExists(sequenceId)
        returns (bool)
    {
        return sequences[sequenceId].sequenceHash == sequenceHash;
    }

    // Function to get DNA sequence details
    function getSequenceDetails(bytes32 sequenceId)
        external
        view
        sequenceExists(sequenceId)
        returns (
            address creator,
            bytes32 sequenceHash,
            string memory metadataURI,
            uint256 createdAt,
            uint256 updatedAt
        )
    {
        require(
            msg.sender == owner ||
            msg.sender == sequences[sequenceId].creator ||
            researchers[msg.sender],
            "Not authorized to view sequence details"
        );

        DNASequence memory sequence = sequences[sequenceId];
        return (
            sequence.creator,
            sequence.sequenceHash,
            sequence.metadataURI,
            sequence.createdAt,
            sequence.updatedAt
        );
    }

    // Function to authorize or deauthorize a researcher
    function setResearcherAuthorization(address researcher, bool authorized) external onlyOwner {
        require(researcher != address(0), "Researcher cannot be zero address");
        require(researchers[researcher] != authorized, "Authorization status already set");

        researchers[researcher] = authorized;
        emit ResearcherAuthorizationUpdated(researcher, authorized, block.timestamp);
    }

    // Function to transfer ownership
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "New owner cannot be zero address");
        researchers[owner] = false; // Remove old owner as researcher
        owner = newOwner;
        researchers[newOwner] = true; // New owner becomes a researcher
        emit ResearcherAuthorizationUpdated(newOwner, true, block.timestamp);
    }
}