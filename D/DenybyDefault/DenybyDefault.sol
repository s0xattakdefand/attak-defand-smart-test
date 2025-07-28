// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// DenyByDefault contract with strict access control
contract DenyByDefault {
    // Contract owner (e.g., administrator)
    address public owner;

    // Structure to store user transaction metadata for rate limiting
    struct TransactionInfo {
        uint256 lastTxTimestamp; // Timestamp of last transaction
        uint256 txCount; // Number of transactions in current window
    }

    // Mapping to store user balances
    mapping(address => uint256) public balances;

    // Mapping to store authorized users for specific actions
    mapping(address => bool) public authorizedUsers;

    // Mapping to store transaction metadata for rate limiting
    mapping(address => TransactionInfo) public userTxInfo;

    // Rate limit parameters to prevent DoS
    uint256 public constant TX_WINDOW = 1 hours; // Time window for rate limiting
    uint256 public constant MAX_TX_PER_WINDOW = 5; // Max transactions per window
    uint256 public constant MIN_TX_INTERVAL = 10 seconds; // Minimum time between transactions

    // Event emitted when tokens are transferred
    event TokensTransferred(address indexed from, address indexed to, uint256 amount, uint256 timestamp);

    // Event emitted when a user is authorized or deauthorized
    event UserAuthorizationUpdated(address indexed user, bool authorized, uint256 timestamp);

    // Event emitted when funds are deposited
    event FundsDeposited(address indexed user, uint256 amount, uint256 timestamp);

    // Event emitted when rate limit is triggered
    event RateLimitTriggered(address indexed user, uint256 timestamp);

    // Modifier to restrict functions to the contract owner
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    // Modifier to restrict functions to authorized users
    modifier onlyAuthorized() {
        require(authorizedUsers[msg.sender], "User not authorized");
        _;
    }

    // Constructor to set the owner and initialize their balance
    constructor() {
        owner = msg.sender;
        authorizedUsers[msg.sender] = true; // Owner is authorized by default
        balances[owner] = 1_000_000 * 10**18; // Initial supply of 1M tokens (18 decimals)
    }

    // Function to deposit funds (accepts Ether for demonstration)
    function deposit() external payable {
        require(msg.value > 0, "Deposit amount must be greater than zero");
        balances[msg.sender] += msg.value; // Convert Ether to tokens (1:1 for simplicity)
        emit FundsDeposited(msg.sender, msg.value, block.timestamp);
    }

    // Function to transfer tokens with rate limiting and authorization
    function transfer(address to, uint256 amount) external onlyAuthorized {
        require(to != address(0), "Recipient cannot be zero address");
        require(amount > 0, "Amount must be greater than zero");
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // Rate limiting to prevent DoS
        TransactionInfo storage txInfo = userTxInfo[msg.sender];
        if (block.timestamp >= txInfo.lastTxTimestamp + TX_WINDOW) {
            txInfo.txCount = 0;
            txInfo.lastTxTimestamp = block.timestamp;
        } else {
            require(
                block.timestamp >= txInfo.lastTxTimestamp + MIN_TX_INTERVAL,
                "Transaction interval too short"
            );
            require(txInfo.txCount < MAX_TX_PER_WINDOW, "Transaction limit exceeded");
            emit RateLimitTriggered(msg.sender, block.timestamp);
        }

        txInfo.txCount += 1;
        txInfo.lastTxTimestamp = block.timestamp;

        // Perform transfer
        balances[msg.sender] -= amount;
        balances[to] += amount;

        emit TokensTransferred(msg.sender, to, amount, block.timestamp);
    }

    // Function to withdraw tokens (converts to Ether for demonstration)
    function withdraw(uint256 amount) external onlyAuthorized {
        require(amount > 0, "Amount must be greater than zero");
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // Update balance before transfer to prevent reentrancy
        balances[msg.sender] -= amount;

        // Transfer Ether using call for gas safety
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Ether transfer failed");

        emit TokensTransferred(msg.sender, address(this), amount, block.timestamp);
    }

    // Function to authorize or deauthorize a user
    function setUserAuthorization(address user, bool authorized) external onlyOwner {
        require(user != address(0), "User cannot be zero address");
        require(authorizedUsers[user] != authorized, "Authorization status already set");

        authorizedUsers[user] = authorized;
        emit UserAuthorizationUpdated(user, authorized, block.timestamp);
    }

    // Function to get user transaction metadata
    function getUserTxInfo(address user) external view returns (uint256 lastTxTimestamp, uint256 txCount) {
        TransactionInfo memory txInfo = userTxInfo[user];
        return (txInfo.lastTxTimestamp, txInfo.txCount);
    }

    // Function to transfer ownership
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "New owner cannot be zero address");
        authorizedUsers[owner] = false; // Remove old owner from authorized users
        owner = newOwner;
        authorizedUsers[newOwner] = true; // New owner is authorized
        emit UserAuthorizationUpdated(newOwner, true, block.timestamp);
    }

    // Fallback function to receive Ether
    receive() external payable {
        if (msg.value > 0) {
            balances[msg.sender] += msg.value;
            emit FundsDeposited(msg.sender, msg.value, block.timestamp);
        }
    }
}