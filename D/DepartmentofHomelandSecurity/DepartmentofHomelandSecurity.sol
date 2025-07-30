// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// DHSSecureContractsAndCredentials contract for managing DHS contract awards and credential verifications
contract DHSSecureContractsAndCredentials {
    // Contract owner (e.g., DHS Office of the Chief Procurement Officer)
    address public owner;

    // Structure to store contract award
    struct ContractAward {
        bytes32 awardId; // Unique identifier for the contract award
        address submitter; // Address of the contracting officer submitting the award
        uint256 amount; // Award amount (in USD, scaled to wei)
        bytes32 dataHash; // Hash of contract details (e.g., scope, deliverables)
        string metadataURI; // Off-chain URI for detailed metadata (e.g., IPFS link)
        uint256 createdAt; // Timestamp when award was submitted
        uint256 updatedAt; // Timestamp of last update
        AwardStatus status; // Status of the award
        address approver; // Address of the approver (e.g., DHS Secretary’s office)
    }

    // Structure to store credential verification
    struct CredentialVerification {
        bytes32 verificationId; // Unique identifier for the verification
        address requester; // Address of the entity requesting verification
        bytes32 credentialHash; // Hash of credential data (e.g., W3C VCDM/DID)
        string metadataURI; // Off-chain URI for verification details
        uint256 timestamp; // Timestamp of verification request
        VerificationStatus status; // Status of the verification
        address verifier; // Address of the entity verifying the credential
    }

    // Enum for contract award status
    enum AwardStatus { Pending, Approved, Rejected }

    // Enum for credential verification status
    enum VerificationStatus { Pending, Verified, Rejected }

    // Structure to store submission metadata for rate limiting
    struct SubmissionInfo {
        uint256 lastSubmissionTimestamp; // Timestamp of last submission
        uint256 submissionCount; // Number of submissions in current window
    }

    // Mapping to store contract awards by award ID
    mapping(bytes32 => ContractAward) public awards;

    // Mapping to store credential verifications by verification ID
    mapping(bytes32 => CredentialVerification) public verifications;

    // Mapping to store authorized entities (e.g., contracting officers, verifiers)
    mapping(address => bool) public authorizedEntities;

    // Mapping to store submission metadata for rate limiting
    mapping(address => SubmissionInfo) public submissionInfo;

    // Rate limit parameters to prevent DoS
    uint256 public constant SUBMISSION_WINDOW = 1 hours; // Time window for rate limiting
    uint256 public constant MAX_SUBMISSIONS_PER_WINDOW = 5; // Max submissions per window
    uint256 public constant MIN_SUBMISSION_INTERVAL = 10 seconds; // Minimum time between submissions

    // Minimum contract award amount requiring approval (e.g., $100,000 scaled to wei)
    uint256 public constant MIN_AWARD_AMOUNT = 100000 * 1e18; // Scaled for wei

    // Event emitted when a contract award is submitted
    event AwardSubmitted(
        bytes32 indexed awardId,
        address indexed submitter,
        uint256 amount,
        bytes32 dataHash,
        string metadataURI,
        uint256 timestamp
    );

    // Event emitted when a contract award is processed
    event AwardProcessed(bytes32 indexed awardId, AwardStatus status, address indexed approver, uint256 timestamp);

    // Event emitted when a credential verification is requested
    event VerificationRequested(
        bytes32 indexed verificationId,
        address indexed requester,
        bytes32 credentialHash,
        string metadataURI,
        uint256 timestamp
    );

    // Event emitted when a credential verification is processed
    event VerificationProcessed(bytes32 indexed verificationId, VerificationStatus status, address indexed verifier, uint256 timestamp);

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

    // Modifier to check if a contract award is pending
    modifier awardPending(bytes32 awardId) {
        require(awards[awardId].status == AwardStatus.Pending, "Award not pending or does not exist");
        _;
    }

    // Modifier to check if a credential verification is pending
    modifier verificationPending(bytes32 verificationId) {
        require(verifications[verificationId].status == VerificationStatus.Pending, "Verification not pending or does not exist");
        _;
    }

    // Constructor to set the owner
    constructor() {
        owner = msg.sender;
        authorizedEntities[msg.sender] = true; // Owner is authorized by default
    }

    // Function to submit a new contract award with rate limiting
    function submitAward(
        bytes32 awardId,
        uint256 amount,
        bytes32 dataHash,
        string calldata metadataURI
    ) external onlyAuthorizedEntity {
        require(awards[awardId].status == AwardStatus.Pending, "Award ID already exists");
        require(amount >= MIN_AWARD_AMOUNT, "Award amount below minimum threshold");
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

        awards[awardId] = ContractAward({
            awardId: awardId,
            submitter: msg.sender,
            amount: amount,
            dataHash: dataHash,
            metadataURI: metadataURI,
            createdAt: block.timestamp,
            updatedAt: block.timestamp,
            status: AwardStatus.Pending,
            approver: address(0)
        });

        emit AwardSubmitted(awardId, msg.sender, amount, dataHash, metadataURI, block.timestamp);
    }

    // Function to approve a contract award
    function approveAward(bytes32 awardId) external onlyAuthorizedEntity awardPending(awardId) {
        awards[awardId].status = AwardStatus.Approved;
        awards[awardId].approver = msg.sender;
        awards[awardId].updatedAt = block.timestamp;

        emit AwardProcessed(awardId, AwardStatus.Approved, msg.sender, block.timestamp);
    }

    // Function to reject a contract award
    function rejectAward(bytes32 awardId) external onlyAuthorizedEntity awardPending(awardId) {
        awards[awardId].status = AwardStatus.Rejected;
        awards[awardId].approver = msg.sender;
        awards[awardId].updatedAt = block.timestamp;

        emit AwardProcessed(awardId, AwardStatus.Rejected, msg.sender, block.timestamp);
    }

    // Function to submit a credential verification request
    function submitVerification(
        bytes32 verificationId,
        bytes32 credentialHash,
        string calldata metadataURI
    ) external onlyAuthorizedEntity {
        require(verifications[verificationId].status == VerificationStatus.Pending, "Verification ID already exists");
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

        verifications[verificationId] = CredentialVerification({
            verificationId: verificationId,
            requester: msg.sender,
            credentialHash: credentialHash,
            metadataURI: metadataURI,
            timestamp: block.timestamp,
            status: VerificationStatus.Pending,
            verifier: address(0)
        });

        emit VerificationRequested(verificationId, msg.sender, credentialHash, metadataURI, block.timestamp);
    }

    // Function to verify a credential
    function verifyCredential(bytes32 verificationId) external onlyAuthorizedEntity verificationPending(verificationId) {
        verifications[verificationId].status = VerificationStatus.Verified;
        verifications[verificationId].verifier = msg.sender;
        verifications[verificationId].timestamp = block.timestamp;

        emit VerificationProcessed(verificationId, VerificationStatus.Verified, msg.sender, block.timestamp);
    }

    // Function to reject a credential verification
    function rejectCredential(bytes32 verificationId) external onlyAuthorizedEntity verificationPending(verificationId) {
        verifications[verificationId].status = VerificationStatus.Rejected;
        verifications[verificationId].verifier = msg.sender;
        verifications[verificationId].timestamp = block.timestamp;

        emit VerificationProcessed(verificationId, VerificationStatus.Rejected, msg.sender, block.timestamp);
    }

    // Function to verify a contract award's data hash
    function verifyAwardHash(bytes32 awardId, bytes32 dataHash) external view returns (bool) {
        return awards[awardId].dataHash == dataHash && awards[awardId].status != AwardStatus.Rejected;
    }

    // Function to verify a credential's hash
    function verifyCredentialHash(bytes32 verificationId, bytes32 credentialHash) external view returns (bool) {
        return verifications[verificationId].credentialHash == credentialHash && verifications[verificationId].status != VerificationStatus.Rejected;
    }

    // Function to get contract award details
    function getAwardDetails(bytes32 awardId)
        external
        view
        returns (
            address submitter,
            uint256 amount,
            bytes32 dataHash,
            string memory metadataURI,
            uint256 createdAt,
            uint256 updatedAt,
            AwardStatus status,
            address approver
        )
    {
        require(
            msg.sender == owner ||
            msg.sender == awards[awardId].submitter ||
            msg.sender == awards[awardId].approver ||
            authorizedEntities[msg.sender],
            "Not authorized to view award details"
        );

        ContractAward memory award = awards[awardId];
        return (
            award.submitter,
            award.amount,
            award.dataHash,
            award.metadataURI,
            award.createdAt,
            award.updatedAt,
            award.status,
            award.approver
        );
    }

    // Function to get credential verification details
    function getVerificationDetails(bytes32 verificationId)
        external
        view
        returns (
            address requester,
            bytes32 credentialHash,
            string memory metadataURI,
            uint256 timestamp,
            VerificationStatus status,
            address verifier
        )
    {
        require(
            msg.sender == owner ||
            msg.sender == verifications[verificationId].requester ||
            msg.sender == verifications[verificationId].verifier ||
            authorizedEntities[msg.sender],
            "Not authorized to view verification details"
        );

        CredentialVerification memory verification = verifications[verificationId];
        return (
            verification.requester,
            verification.credentialHash,
            verification.metadataURI,
            verification.timestamp,
            verification.status,
            verification.verifier
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