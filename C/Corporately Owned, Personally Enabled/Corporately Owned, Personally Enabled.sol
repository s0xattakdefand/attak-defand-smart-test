// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CorporatePersonalEnabled {
    address public admin;
    uint256 public requiredApprovals;

    struct User {
        bool authorized;
        uint256 dailyLimit;
        uint256 usedToday;
        uint256 lastInteractionDay;
    }

    mapping(address => User) public users;
    mapping(uint256 => Transaction) public transactions;
    uint256 public txCount;

    struct Transaction {
        address initiator;
        address to;
        uint256 amount;
        uint256 approvals;
        bool executed;
        mapping(address => bool) approvedBy;
    }

    event UserAuthorized(address indexed user, uint256 dailyLimit);
    event TransactionProposed(uint256 indexed txId, address to, uint256 amount);
    event TransactionApproved(uint256 indexed txId, address approver, uint256 approvals);
    event TransactionExecuted(uint256 indexed txId, address to, uint256 amount);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier onlyAuthorized() {
        require(users[msg.sender].authorized, "Not authorized");
        _;
    }

    constructor(uint256 _requiredApprovals) {
        admin = msg.sender;
        requiredApprovals = _requiredApprovals;
    }

    // Admin authorizes users with daily asset limits
    function authorizeUser(address user, uint256 dailyLimit) external onlyAdmin {
        users[user] = User(true, dailyLimit, 0, block.timestamp / 1 days);
        emit UserAuthorized(user, dailyLimit);
    }

    // Users propose transactions within their limits
    function proposeTransaction(address to, uint256 amount) external onlyAuthorized {
        User storage user = users[msg.sender];

        // Reset daily limit if new day
        if (user.lastInteractionDay < block.timestamp / 1 days) {
            user.usedToday = 0;
            user.lastInteractionDay = block.timestamp / 1 days;
        }

        require(user.usedToday + amount <= user.dailyLimit, "Daily limit exceeded");

        transactions[txCount].initiator = msg.sender;
        transactions[txCount].to = to;
        transactions[txCount].amount = amount;
        transactions[txCount].approvals = 0;
        transactions[txCount].executed = false;

        emit TransactionProposed(txCount, to, amount);
        txCount++;
    }

    // Authorized approvers approve transactions
    function approveTransaction(uint256 txId) external onlyAuthorized {
        Transaction storage txn = transactions[txId];
        require(!txn.executed, "Already executed");
        require(!txn.approvedBy[msg.sender], "Already approved");

        txn.approvedBy[msg.sender] = true;
        txn.approvals++;

        emit TransactionApproved(txId, msg.sender, txn.approvals);

        if (txn.approvals >= requiredApprovals) {
            executeTransaction(txId);
        }
    }

    // Internal execution after multisig approval
    function executeTransaction(uint256 txId) internal {
        Transaction storage txn = transactions[txId];
        require(!txn.executed, "Already executed");
        require(txn.approvals >= requiredApprovals, "Insufficient approvals");

        txn.executed = true;

        // Update user daily usage
        User storage user = users[txn.initiator];
        user.usedToday += txn.amount;

        payable(txn.to).transfer(txn.amount);
        emit TransactionExecuted(txId, txn.to, txn.amount);
    }

    // Allow contract to receive funds
    receive() external payable {}

    // Check transaction status
    function getTransaction(uint256 txId) external view returns (
        address initiator, address to, uint256 amount, uint256 approvals, bool executed
    ) {
        Transaction storage txn = transactions[txId];
        return (txn.initiator, txn.to, txn.amount, txn.approvals, txn.executed);
    }
}
