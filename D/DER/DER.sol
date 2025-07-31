// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// DERManager contract for managing Distributed Energy Resources (DER) operations and compliance
contract DERManager {
    // Contract owner (e.g., DoE Program Office)
    address public owner;

    // Structure to store DER contribution (e.g., energy produced or stored)
    struct DERContribution {
        bytes32 contributionId; // Unique identifier for the contribution
        address contributor; // Address of the DER provider (e.g., solar panel owner)
        string resourceType; // Type of DER (e.g., Solar, Wind, Battery)
        uint256 energyAmount; // Energy contributed in kWh
        bytes32 dataHash; // Hash of contribution details (using keccak256)
        string metadataURI; // Off-chain URI for detailed metadata (e.g., IPFS link)
        uint256 timestamp; // Timestamp of contribution submission
        ContributionStatus status; // Status of the contribution
        address reviewer; // Address of the entity reviewing the contribution
    }

    // Structure to store energy trade
    struct EnergyTrade {
        bytes32 tradeId; // Unique identifier for the trade
        address seller; // Address of the energy seller
        address buyer; // Address of the energy buyer
        uint256 energyAmount; // Energy traded in kWh
        uint256 price; // Price in wei per kWh
        bytes32 dataHash; // Hash of trade details
        string metadataURI; // Off-chain URI for trade details
        uint256 timestamp; // Timestamp of trade initiation
        TradeStatus status; // Status of the trade
        address reviewer; // Address of the entity approving/rejecting the trade
    }

    // Structure to store compliance record
    struct ComplianceRecord {
        bytes32 recordId; // Unique identifier for the compliance record
        address entity; // Address of the entity submitting compliance data
        string complianceType; // Type of compliance (e.g., NIST 800-171, FAR)
        bytes32 dataHash; // Hash of compliance evidence
        string metadataURI; // Off-chain URI for compliance details
        uint256 timestamp; // Timestamp of record submission
        ComplianceStatus status; // Status of the compliance record
        address reviewer; // Address of the entity reviewing compliance
    }

    // Enum for contribution status
    enum ContributionStatus { Pending, Verified, Rejected, Settled }

    // Enum for trade status
    enum TradeStatus { Pending, Approved, Rejected, Executed }

    // Enum for compliance status
    enum ComplianceStatus { Pending, Approved, Rejected }

    // Structure to store submission metadata for rate limiting
    struct SubmissionInfo {
        uint256 lastSubmissionTimestamp; // Timestamp of last submission
        uint256 submissionCount; // Number of submissions in current window
    }

    // Mapping to store DER contributions by contribution ID
    mapping(bytes32 => DERContribution) public contributions;

    // Mapping to store energy trades by trade ID
    mapping(bytes32 => EnergyTrade) public trades;

    // Mapping to store compliance records by record ID
    mapping(bytes32 => ComplianceRecord) public complianceRecords;

    // Mapping to store authorized entities (e.g., DER providers, grid operators)
    mapping(address => bool) public authorizedEntities;

    // Mapping to store submission metadata for rate limiting
    mapping(address => SubmissionInfo) public submissionInfo;

    // Rate limit parameters to prevent DoS
    uint256 public constant SUBMISSION_WINDOW = 1 hours; // Time window for rate limiting
    uint256 public constant MAX_SUBMISSIONS_PER_WINDOW = 5; // Max submissions per window
    uint256 public constant MIN_SUBMISSION_INTERVAL = 10 seconds; // Minimum time between submissions

    // Maximum energy amount per contribution (in kWh) to prevent overflow
    uint256 public constant MAX_ENERGY_AMOUNT = 1_000_000; // 1 GWh

    // Event emitted when a DER contribution is submitted
    event ContributionSubmitted(
        bytes32 indexed contributionId,
        address indexed contributor,
        string resourceType,
        uint256 energyAmount,
        bytes32 dataHash,
        string metadataURI,
        uint256 timestamp
    );

    // Event emitted when a DER contribution is processed
    event ContributionProcessed(
        bytes32 indexed contributionId,
        ContributionStatus status,
        address indexed reviewer,
        uint256 timestamp
    );

    // Event emitted when an energy trade is initiated
    event TradeInitiated(
        bytes32 indexed tradeId,
        address indexed seller,
        address indexed buyer,
        uint256 energyAmount,
        uint256 price,
        bytes32 dataHash,
        string metadataURI,
        uint256 timestamp
    );

    // Event emitted when an energy trade is processed
    event TradeProcessed(
        bytes32 indexed tradeId,
        TradeStatus status,
        address indexed reviewer,
        uint256 timestamp
    );

    // Event emitted when a compliance record is submitted
    event ComplianceRecordSubmitted(
        bytes32 indexed recordId,
        address indexed entity,
        string complianceType,
        bytes32 dataHash,
        string metadataURI,
        uint256 timestamp
    );

    // Event emitted when a compliance record is processed
    event ComplianceRecordProcessed(
        bytes32 indexed recordId,
        ComplianceStatus status,
        address indexed reviewer,
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

    // Modifier to check if a contribution is pending
    modifier contributionPending(bytes32 contributionId) {
        if (contributions[contributionId].status != ContributionStatus.Pending) {
            revert("Contribution not pending or does not exist");
        }
        _;
    }

    // Modifier to check if a trade is pending
    modifier tradePending(bytes32 tradeId) {
        if (trades[tradeId].status != TradeStatus.Pending) {
            revert("Trade not pending or does not exist");
        }
        _;
    }

    // Modifier to check if a compliance record is pending
    modifier compliancePending(bytes32 recordId) {
        if (complianceRecords[recordId].status != ComplianceStatus.Pending) {
            revert("Compliance record not pending or does not exist");
        }
        _;
    }

    // Constructor to set the owner
    constructor() {
        owner = msg.sender;
        authorizedEntities[msg.sender] = true; // Owner is authorized by default
    }

    // Function to submit a new DER contribution with rate limiting
    function submitContribution(
        bytes32 contributionId,
        string calldata resourceType,
        uint256 energyAmount,
        bytes32 dataHash,
        string calldata metadataURI
    ) external onlyAuthorizedEntity {
        if (contributions[contributionId].status != ContributionStatus.Pending) {
            revert("Contribution ID already exists");
        }
        if (bytes(resourceType).length == 0 || bytes(resourceType).length > 50) {
            revert("Invalid resource type length");
        }
        if (energyAmount == 0 || energyAmount > MAX_ENERGY_AMOUNT) {
            revert("Invalid energy amount");
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

        contributions[contributionId] = DERContribution({
            contributionId: contributionId,
            contributor: msg.sender,
            resourceType: resourceType,
            energyAmount: energyAmount,
            dataHash: dataHash,
            metadataURI: metadataURI,
            timestamp: block.timestamp,
            status: ContributionStatus.Pending,
            reviewer: address(0)
        });

        emit ContributionSubmitted(
            contributionId,
            msg.sender,
            resourceType,
            energyAmount,
            dataHash,
            metadataURI,
            block.timestamp
        );
    }

    // Function to verify a DER contribution
    function verifyContribution(bytes32 contributionId) external onlyAuthorizedEntity contributionPending(contributionId) {
        contributions[contributionId].status = ContributionStatus.Verified;
        contributions[contributionId].reviewer = msg.sender;
        contributions[contributionId].timestamp = block.timestamp;

        emit ContributionProcessed(contributionId, ContributionStatus.Verified, msg.sender, block.timestamp);
    }

    // Function to reject a DER contribution
    function rejectContribution(bytes32 contributionId) external onlyAuthorizedEntity contributionPending(contributionId) {
        contributions[contributionId].status = ContributionStatus.Rejected;
        contributions[contributionId].reviewer = msg.sender;
        contributions[contributionId].timestamp = block.timestamp;

        emit ContributionProcessed(contributionId, ContributionStatus.Rejected, msg.sender, block.timestamp);
    }

    // Function to settle a DER contribution (e.g., after grid integration)
    function settleContribution(bytes32 contributionId) external onlyAuthorizedEntity {
        if (contributions[contributionId].status != ContributionStatus.Verified) {
            revert("Contribution must be verified to settle");
        }
        contributions[contributionId].status = ContributionStatus.Settled;
        contributions[contributionId].timestamp = block.timestamp;

        emit ContributionProcessed(contributionId, ContributionStatus.Settled, msg.sender, block.timestamp);
    }

    // Function to initiate an energy trade
    function initiateTrade(
        bytes32 tradeId,
        address buyer,
        uint256 energyAmount,
        uint256 price,
        bytes32 dataHash,
        string calldata metadataURI
    ) external onlyAuthorizedEntity {
        if (trades[tradeId].status != TradeStatus.Pending) {
            revert("Trade ID already exists");
        }
        if (buyer == address(0) || buyer == msg.sender) {
            revert("Invalid buyer address");
        }
        if (energyAmount == 0 || energyAmount > MAX_ENERGY_AMOUNT) {
            revert("Invalid energy amount");
        }
        if (price == 0) {
            revert("Price must be greater than zero");
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

        trades[tradeId] = EnergyTrade({
            tradeId: tradeId,
            seller: msg.sender,
            buyer: buyer,
            energyAmount: energyAmount,
            price: price,
            dataHash: dataHash,
            metadataURI: metadataURI,
            timestamp: block.timestamp,
            status: TradeStatus.Pending,
            reviewer: address(0)
        });

        emit TradeInitiated(tradeId, msg.sender, buyer, energyAmount, price, dataHash, metadataURI, block.timestamp);
    }

    // Function to approve an energy trade
    function approveTrade(bytes32 tradeId) external onlyAuthorizedEntity tradePending(tradeId) {
        trades[tradeId].status = TradeStatus.Approved;
        trades[tradeId].reviewer = msg.sender;
        trades[tradeId].timestamp = block.timestamp;

        emit TradeProcessed(tradeId, TradeStatus.Approved, msg.sender, block.timestamp);
    }

    // Function to reject an energy trade
    function rejectTrade(bytes32 tradeId) external onlyAuthorizedEntity tradePending(tradeId) {
        trades[tradeId].status = TradeStatus.Rejected;
        trades[tradeId].reviewer = msg.sender;
        trades[tradeId].timestamp = block.timestamp;

        emit TradeProcessed(tradeId, TradeStatus.Rejected, msg.sender, block.timestamp);
    }

    // Function to execute an energy trade (payment and energy transfer)
    function executeTrade(bytes32 tradeId) external payable onlyAuthorizedEntity {
        EnergyTrade storage trade = trades[tradeId];
        if (trade.status != TradeStatus.Approved) {
            revert("Trade must be approved to execute");
        }
        if (msg.sender != trade.buyer) {
            revert("Only buyer can execute trade");
        }
        if (msg.value < trade.energyAmount * trade.price) {
            revert("Insufficient payment");
        }

        trade.status = TradeStatus.Executed;
        trade.timestamp = block.timestamp;

        // Transfer payment to seller
        (bool success, ) = trade.seller.call{value: msg.value}("");
        if (!success) {
            revert("Payment transfer failed");
        }

        emit TradeProcessed(tradeId, TradeStatus.Executed, msg.sender, block.timestamp);
    }

    // Function to submit a compliance record
    function submitComplianceRecord(
        bytes32 recordId,
        string calldata complianceType,
        bytes32 dataHash,
        string calldata metadataURI
    ) external onlyAuthorizedEntity {
        if (complianceRecords[recordId].status != ComplianceStatus.Pending) {
            revert("Record ID already exists");
        }
        if (bytes(complianceType).length == 0 || bytes(complianceType).length > 50) {
            revert("Invalid compliance type length");
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

        complianceRecords[recordId] = ComplianceRecord({
            recordId: recordId,
            entity: msg.sender,
            complianceType: complianceType,
            dataHash: dataHash,
            metadataURI: metadataURI,
            timestamp: block.timestamp,
            status: ComplianceStatus.Pending,
            reviewer: address(0)
        });

        emit ComplianceRecordSubmitted(recordId, msg.sender, complianceType, dataHash, metadataURI, block.timestamp);
    }

    // Function to approve a compliance record
    function approveComplianceRecord(bytes32 recordId) external onlyAuthorizedEntity compliancePending(recordId) {
        complianceRecords[recordId].status = ComplianceStatus.Approved;
        complianceRecords[recordId].reviewer = msg.sender;
        complianceRecords[recordId].timestamp = block.timestamp;

        emit ComplianceRecordProcessed(recordId, ComplianceStatus.Approved, msg.sender, block.timestamp);
    }

    // Function to reject a compliance record
    function rejectComplianceRecord(bytes32 recordId) external onlyAuthorizedEntity compliancePending(recordId) {
        complianceRecords[recordId].status = ComplianceStatus.Rejected;
        complianceRecords[recordId].reviewer = msg.sender;
        complianceRecords[recordId].timestamp = block.timestamp;

        emit ComplianceRecordProcessed(recordId, ComplianceStatus.Rejected, msg.sender, block.timestamp);
    }

    // Function to verify a contribution's data hash
    function verifyContributionHash(bytes32 contributionId, bytes32 dataHash) external view returns (bool) {
        return contributions[contributionId].dataHash == dataHash && contributions[contributionId].status != ContributionStatus.Rejected;
    }

    // Function to verify a trade's data hash
    function verifyTradeHash(bytes32 tradeId, bytes32 dataHash) external view returns (bool) {
        return trades[tradeId].dataHash == dataHash && trades[tradeId].status != TradeStatus.Rejected;
    }

    // Function to verify a compliance record's data hash
    function verifyComplianceHash(bytes32 recordId, bytes32 dataHash) external view returns (bool) {
        return complianceRecords[recordId].dataHash == dataHash && complianceRecords[recordId].status != ComplianceStatus.Rejected;
    }

    // Function to get DER contribution details
    function getContributionDetails(bytes32 contributionId)
        external
        view
        returns (
            address contributor,
            string memory resourceType,
            uint256 energyAmount,
            bytes32 dataHash,
            string memory metadataURI,
            uint256 timestamp,
            ContributionStatus status,
            address reviewer
        )
    {
        if (
            msg.sender != owner &&
            msg.sender != contributions[contributionId].contributor &&
            msg.sender != contributions[contributionId].reviewer &&
            !authorizedEntities[msg.sender]
        ) {
            revert("Not authorized to view contribution details");
        }

        DERContribution memory contribution = contributions[contributionId];
        return (
            contribution.contributor,
            contribution.resourceType,
            contribution.energyAmount,
            contribution.dataHash,
            contribution.metadataURI,
            contribution.timestamp,
            contribution.status,
            contribution.reviewer
        );
    }

    // Function to get energy trade details
    function getTradeDetails(bytes32 tradeId)
        external
        view
        returns (
            address seller,
            address buyer,
            uint256 energyAmount,
            uint256 price,
            bytes32 dataHash,
            string memory metadataURI,
            uint256 timestamp,
            TradeStatus status,
            address reviewer
        )
    {
        if (
            msg.sender != owner &&
            msg.sender != trades[tradeId].seller &&
            msg.sender != trades[tradeId].buyer &&
            msg.sender != trades[tradeId].reviewer &&
            !authorizedEntities[msg.sender]
        ) {
            revert("Not authorized to view trade details");
        }

        EnergyTrade memory trade = trades[tradeId];
        return (
            trade.seller,
            trade.buyer,
            trade.energyAmount,
            trade.price,
            trade.dataHash,
            trade.metadataURI,
            trade.timestamp,
            trade.status,
            trade.reviewer
        );
    }

    // Function to get compliance record details
    function getComplianceRecordDetails(bytes32 recordId)
        external
        view
        returns (
            address entity,
            string memory complianceType,
            bytes32 dataHash,
            string memory metadataURI,
            uint256 timestamp,
            ComplianceStatus status,
            address reviewer
        )
    {
        if (
            msg.sender != owner &&
            msg.sender != complianceRecords[recordId].entity &&
            msg.sender != complianceRecords[recordId].reviewer &&
            !authorizedEntities[msg.sender]
        ) {
            revert("Not authorized to view compliance record details");
        }

        ComplianceRecord memory record = complianceRecords[recordId];
        return (
            record.entity,
            record.complianceType,
            record.dataHash,
            record.metadataURI,
            record.timestamp,
            record.status,
            record.reviewer
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