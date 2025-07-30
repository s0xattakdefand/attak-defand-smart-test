// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// DoEEnergyTrading contract for managing Department of Energy P2P energy trading and RECs
contract DoEEnergyTrading {
    // Contract owner (e.g., DoE Office of Energy Efficiency and Renewable Energy)
    address public owner;

    // Structure to store energy transaction
    struct EnergyTransaction {
        bytes32 transactionId; // Unique identifier for the transaction
        address seller; // Address of the energy seller (prosumer)
        address buyer; // Address of the energy buyer
        uint256 energyAmount; // Amount of energy traded (in kWh)
        uint256 tokenAmount; // Amount of tokens paid (in ERC-20 energy credits)
        bytes32 dataHash; // Hash of transaction data (e.g., meter readings)
        string metadataURI; // Off-chain URI for detailed metadata (e.g., IPFS link)
        uint256 timestamp; // Timestamp of transaction
        TransactionStatus status; // Status of the transaction
    }

    // Enum for transaction status
    enum TransactionStatus { Pending, Completed, Cancelled }

    // Structure to store submission metadata for rate limiting
    struct SubmissionInfo {
        uint256 lastSubmissionTimestamp; // Timestamp of last submission
        uint256 submissionCount; // Number of submissions in current window
    }

    // Mapping to store energy transactions by transaction ID
    mapping(bytes32 => EnergyTransaction) public transactions;

    // Mapping to store authorized prosumers (e.g., solar panel owners, grid operators)
    mapping(address => bool) public authorizedProsumers;

    // Mapping to store submission metadata for rate limiting
    mapping(address => SubmissionInfo) public submissionInfo;

    // ERC-20 token for energy credits (e.g., RECs)
    address public energyToken;

    // Rate limit parameters to prevent DoS
    uint256 public constant SUBMISSION_WINDOW = 1 hours; // Time window for rate limiting
    uint256 public constant MAX_SUBMISSIONS_PER_WINDOW = 5; // Max submissions per window
    uint256 public constant MIN_SUBMISSION_INTERVAL = 10 seconds; // Minimum time between submissions

    // Event emitted when an energy transaction is submitted
    event TransactionSubmitted(
        bytes32 indexed transactionId,
        address indexed seller,
        address indexed buyer,
        uint256 energyAmount,
        uint256 tokenAmount,
        bytes32 dataHash,
        string metadataURI,
        uint256 timestamp
    );

    // Event emitted when a transaction is completed or cancelled
    event TransactionProcessed(bytes32 indexed transactionId, TransactionStatus status, uint256 timestamp);

    // Event emitted when an entity is authorized or deauthorized
    event EntityAuthorizationUpdated(address indexed entity, bool authorized, uint256 timestamp);

    // Event emitted when rate limit is triggered
    event RateLimitTriggered(address indexed entity, uint256 timestamp);

    // Modifier to restrict functions to the contract owner
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    // Modifier to restrict functions to authorized prosumers
    modifier onlyAuthorizedProsumer() {
        require(authorizedProsumers[msg.sender], "Only authorized prosumers can call this function");
        _;
    }

    // Modifier to check if a transaction is pending
    modifier transactionPending(bytes32 transactionId) {
        require(transactions[transactionId].status == TransactionStatus.Pending, "Transaction not pending or does not exist");
        _;
    }

    // Constructor to set the owner and energy token address
    constructor(address _energyToken) {
        require(_energyToken != address(0), "Energy token address cannot be zero");
        owner = msg.sender;
        energyToken = _energyToken;
        authorizedProsumers[msg.sender] = true; // Owner is authorized by default
    }

    // Function to submit a new energy transaction with rate limiting
    function submitTransaction(
        bytes32 transactionId,
        address buyer,
        uint256 energyAmount,
        uint256 tokenAmount,
        bytes32 dataHash,
        string calldata metadataURI
    ) external onlyAuthorizedProsumer {
        require(transactions[transactionId].status == TransactionStatus.Pending, "Transaction ID already exists");
        require(buyer != address(0), "Buyer address cannot be zero");
        require(energyAmount > 0, "Energy amount must be greater than zero");
        require(tokenAmount > 0, "Token amount must be greater than zero");
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

        transactions[transactionId] = EnergyTransaction({
            transactionId: transactionId,
            seller: msg.sender,
            buyer: buyer,
            energyAmount: energyAmount,
            tokenAmount: tokenAmount,
            dataHash: dataHash,
            metadataURI: metadataURI,
            timestamp: block.timestamp,
            status: TransactionStatus.Pending
        });

        emit TransactionSubmitted(transactionId, msg.sender, buyer, energyAmount, tokenAmount, dataHash, metadataURI, block.timestamp);
    }

    // Function to complete a transaction (transfer tokens and confirm)
    function completeTransaction(bytes32 transactionId) external transactionPending(transactionId) {
        EnergyTransaction storage transaction = transactions[transactionId];
        require(msg.sender == transaction.seller || msg.sender == transaction.buyer, "Only seller or buyer can complete");

        // Transfer tokens from buyer to seller using ERC-20 interface
        require(IERC20(energyToken).transferFrom(transaction.buyer, transaction.seller, transaction.tokenAmount), "Token transfer failed");

        transaction.status = TransactionStatus.Completed;
        transaction.timestamp = block.timestamp;

        emit TransactionProcessed(transactionId, TransactionStatus.Completed, block.timestamp);
    }

    // Function to cancel a transaction
    function cancelTransaction(bytes32 transactionId) external transactionPending(transactionId) onlyAuthorizedProsumer {
        EnergyTransaction storage transaction = transactions[transactionId];
        require(msg.sender == transaction.seller, "Only seller can cancel");

        transaction.status = TransactionStatus.Cancelled;
        transaction.timestamp = block.timestamp;

        emit TransactionProcessed(transactionId, TransactionStatus.Cancelled, block.timestamp);
    }

    // Function to verify a transaction's data hash
    function verifyTransactionHash(bytes32 transactionId, bytes32 dataHash) external view returns (bool) {
        return transactions[transactionId].dataHash == dataHash && transactions[transactionId].status != TransactionStatus.Cancelled;
    }

    // Function to get transaction details
    function getTransactionDetails(bytes32 transactionId)
        external
        view
        returns (
            address seller,
            address buyer,
            uint256 energyAmount,
            uint256 tokenAmount,
            bytes32 dataHash,
            string memory metadataURI,
            uint256 timestamp,
            TransactionStatus status
        )
    {
        require(
            msg.sender == owner ||
            msg.sender == transactions[transactionId].seller ||
            msg.sender == transactions[transactionId].buyer ||
            authorizedProsumers[msg.sender],
            "Not authorized to view transaction details"
        );

        EnergyTransaction memory transaction = transactions[transactionId];
        return (
            transaction.seller,
            transaction.buyer,
            transaction.energyAmount,
            transaction.tokenAmount,
            transaction.dataHash,
            transaction.metadataURI,
            transaction.timestamp,
            transaction.status
        );
    }

    // Function to authorize or deauthorize a prosumer
    function setProsumerAuthorization(address prosumer, bool authorized) external onlyOwner {
        require(prosumer != address(0), "Prosumer address cannot be zero");
        require(authorizedProsumers[prosumer] != authorized, "Authorization status already set");

        authorizedProsumers[prosumer] = authorized;
        emit EntityAuthorizationUpdated(prosumer, authorized, block.timestamp);
    }

    // Function to transfer ownership
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "New owner cannot be zero address");
        authorizedProsumers[owner] = false; // Remove old owner as authorized prosumer
        owner = newOwner;
        authorizedProsumers[newOwner] = true; // New owner becomes authorized
        emit EntityAuthorizationUpdated(newOwner, true, block.timestamp);
    }
}

// Interface for ERC-20 token interactions
interface IERC20 {
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
}