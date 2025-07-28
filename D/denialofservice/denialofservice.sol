// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// DoSMitigation contract with protections against denial of service vulnerabilities
contract DoSMitigation {
    // Contract owner (e.g., administrator)
    address public owner;

    // Structure to store user transaction metadata
    struct UserTransaction {
        uint256 lastTxTimestamp; // Timestamp of last transaction
        uint256 txCount; // Number of transactions in current window
    }

    // Mapping to store user balances
    mapping(address => uint256) public balances;

    // Mapping to store user transaction metadata
    mapping(address => UserTransaction) public userTxs;

    // Rate limit parameters
    uint256 public constant TX_WINDOW = 1 hours; // Time window for rate limiting
    uint256 public constant MAX_TX_PER_WINDOW = 10; // Max transactions per window
    uint256 public constant MIN_TX_INTERVAL = 10 seconds; // Minimum time between transactions

    // Event emitted when tokens are transferred
    event TokensTransferred(address indexed from, address indexed to, uint256 amount, uint256 timestamp);

    // Event emitted when a user is rate-limited
    event RateLimitTriggered(address indexed user, uint256 timestamp);

    // Event emitted when funds are deposited
    event FundsDeposited(address indexed user, uint256 amount, uint256 timestamp);

    // Modifier to restrict functions to the contract owner
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    // Constructor to set the owner and initialize their balance
    constructor() {
        owner = msg.sender;
        balances[owner] = 1_000_000 * 10**18; // Initial supply of 1M tokens (18 decimals)
    }

    // Function to deposit funds (for demonstration, accepts Ether)
    function deposit() external payable {
        require(msg.value > 0, "Deposit amount must be greater than zero");
        balances[msg.sender] += msg.value; // Convert Ether to tokens (1:1 for simplicity)
        emit FundsDeposited(msg.sender, msg.value, block.timestamp);
    }

    // Function to transfer tokens with rate limiting
    function transfer(address to, uint256 amount) external {
        require(to != address(0), "Recipient cannot be zero address");
        require(amount > 0, "Amount must be greater than zero");
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // Check rate limiting
        UserTransaction storage userTx = userTxs[msg.sender];
        if (block.timestamp >= userTx.lastTxTimestamp + TX_WINDOW) {
            // Reset transaction count if window has passed
            userTx.txCount = 0;
            userTx.lastTxTimestamp = block.timestamp;
        } else {
            // Enforce minimum interval between transactions
            require(
                block.timestamp >= userTx.lastTxTimestamp + MIN_TX_INTERVAL,
                "Transaction interval too short"
            );
            // Enforce max transactions per window
            require(userTx.txCount < MAX_TX_PER_WINDOW, "Transaction limit exceeded");
            emit RateLimitTriggered(msg.sender, block.timestamp);
        }

        // Update transaction metadata
        userTx.txCount += 1;
        userTx.lastTxTimestamp = block.timestamp;

        // Perform transfer (pull over push to avoid gas limit issues)
        balances[msg.sender] -= amount;
        balances[to] += amount;

        emit TokensTransferred(msg.sender, to, amount, block.timestamp);
    }

    // Function to withdraw tokens (for demonstration, converts tokens to Ether)
    function withdraw(uint256 amount) external {
        require(amount > 0, "Amount must be greater than zero");
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // Update balance before transfer to prevent reentrancy
        balances[msg.sender] -= amount;

        // Transfer Ether (using call to avoid gas limit issues with send/transfer)
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Ether transfer failed");

        emit TokensTransferred(msg.sender, address(this), amount, block.timestamp);
    }

    // Function to get user transaction metadata
    function getUserTxInfo(address user) external view returns (uint256 lastTxTimestamp, uint256 txCount) {
        UserTransaction memory userTx = userTxs[user];
        return (userTx.lastTxTimestamp, userTx.txCount);
    }

    // Function to transfer ownership
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "New owner cannot be zero address");
        owner = newOwner;
    }

    // Fallback function to receive Ether
    receive() external payable {
        if (msg.value > 0) {
            balances[msg.sender] += msg.value;
            emit FundsDeposited(msg.sender, msg.value, block.timestamp);
        }
    }
}