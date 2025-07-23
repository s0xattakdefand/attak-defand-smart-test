// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

/**
 * @title DeFiLending
 * @notice A decentralized lending platform for depositing and borrowing ERC-20 tokens.
 * @dev Uses OpenZeppelin for secure ERC-20 interactions and reentrancy protection.
 */
contract DeFiLending is ReentrancyGuard {
    using SafeMath for uint256;

    // Struct to store user balance and interest
    struct UserAccount {
        uint256 depositBalance; // Amount of tokens deposited
        uint256 debt; // Amount of tokens borrowed
        uint256 lastInterestUpdate; // Timestamp of last interest calculation
        uint256 accruedInterest; // Interest earned on deposits
    }

    // Contract parameters
    IERC20 public token; // ERC-20 token used for deposits and loans
    address public owner; // Contract deployer, with admin privileges
    uint256 public constant ANNUAL_INTEREST_RATE = 5; // 5% annual interest for deposits
    uint256 public constant BORROW_INTEREST_RATE = 10; // 10% annual interest for loans
    uint256 public constant COLLATERAL_RATIO = 150; // 150% collateralization ratio
    uint256 public constant SECONDS_PER_YEAR = 365 days;

    // Storage
    mapping(address => UserAccount) private _accounts;
    uint256 public totalDeposits; // Total tokens deposited in the contract
    uint256 public totalDebt; // Total tokens borrowed

    // Events for transparency
    event Deposited(address indexed user, uint256 amount, uint256 timestamp);
    event Withdrawn(address indexed user, uint256 amount, uint256 interest, uint256 timestamp);
    event Borrowed(address indexed user, uint256 amount, uint256 timestamp);
    event Repaid(address indexed user, uint256 amount, uint256 timestamp);

    // Modifiers
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier nonZeroAmount(uint256 amount) {
        require(amount > 0, "Amount must be greater than zero");
        _;
    }

    // Constructor
    constructor(address _token) {
        require(_token != address(0), "Invalid token address");
        token = IERC20(_token);
        owner = msg.sender;
    }

    /// @notice Calculate accrued interest for a user
    function calculateInterest(address user) public view returns (uint256) {
        UserAccount memory account = _accounts[user];
        if (account.depositBalance == 0) return account.accruedInterest;

        uint256 timeElapsed = block.timestamp.sub(account.lastInterestUpdate);
        uint256 interest = account.depositBalance
            .mul(ANNUAL_INTEREST_RATE)
            .mul(timeElapsed)
            .div(100)
            .div(SECONDS_PER_YEAR);
        return account.accruedInterest.add(interest);
    }

    /// @notice Deposit tokens to earn interest
    function deposit(uint256 amount) external nonReentrant nonZeroAmount(amount) {
        require(token.transferFrom(msg.sender, address(this), amount), "Transfer failed");
        UserAccount storage account = _accounts[msg.sender];
        account.accruedInterest = calculateInterest(msg.sender);
        account.depositBalance = account.depositBalance.add(amount);
        account.lastInterestUpdate = block.timestamp;
        totalDeposits = totalDeposits.add(amount);
        emit Deposited(msg.sender, amount, block.timestamp);
    }

    /// @notice Withdraw deposited tokens and accrued interest
    function withdraw(uint256 amount) external nonReentrant nonZeroAmount(amount) {
        UserAccount storage account = _accounts[msg.sender];
        require(account.depositBalance >= amount, "Insufficient deposit balance");
        account.accruedInterest = calculateInterest(msg.sender);
        account.depositBalance = account.depositBalance.sub(amount);
        account.lastInterestUpdate = block.timestamp;
        totalDeposits = totalDeposits.sub(amount);
        uint256 interest = account.accruedInterest;
        account.accruedInterest = 0;
        require(token.transfer(msg.sender, amount.add(interest)), "Transfer failed");
        emit Withdrawn(msg.sender, amount, interest, block.timestamp);
    }

    /// @notice Borrow tokens against collateral
    function borrow(uint256 amount) external nonReentrant nonZeroAmount(amount) {
        UserAccount storage account = _accounts[msg.sender];
        account.accruedInterest = calculateInterest(msg.sender);
        uint256 maxBorrow = account.depositBalance
            .mul(COLLATERAL_RATIO)
            .div(100);
        require(maxBorrow >= account.debt.add(amount), "Insufficient collateral");
        account.debt = account.debt.add(amount);
        account.lastInterestUpdate = block.timestamp;
        totalDebt = totalDebt.add(amount);
        require(token.transfer(msg.sender, amount), "Transfer failed");
        emit Borrowed(msg.sender, amount, block.timestamp);
    }

    /// @notice Repay borrowed tokens with interest
    function repay(uint256 amount) external nonReentrant nonZeroAmount(amount) {
        UserAccount storage account = _accounts[msg.sender];
        require(account.debt > 0, "No debt to repay");
        uint256 interest = account.debt
            .mul(BORROW_INTEREST_RATE)
            .mul(block.timestamp.sub(account.lastInterestUpdate))
            .div(100)
            .div(SECONDS_PER_YEAR);
        uint256 totalRepayment = amount.add(interest);
        require(totalRepayment <= account.debt.add(interest), "Repayment exceeds debt");
        require(token.transferFrom(msg.sender, address(this), totalRepayment), "Transfer failed");
        account.debt = account.debt.sub(amount);
        account.lastInterestUpdate = block.timestamp;
        totalDebt = totalDebt.sub(amount);
        emit Repaid(msg.sender, amount, block.timestamp);
    }

    /// @notice Get user account details
    function getAccount(address user) external view returns (UserAccount memory) {
        return UserAccount({
            depositBalance: _accounts[user].depositBalance,
            debt: _accounts[user].debt,
            lastInterestUpdate: _accounts[user].lastInterestUpdate,
            accruedInterest: calculateInterest(user)
        });
    }

    /// @notice Emergency stop to withdraw all funds (owner only)
    function emergencyWithdraw() external onlyOwner nonReentrant {
        uint256 balance = token.balanceOf(address(this));
        require(balance > 0, "No funds to withdraw");
        require(token.transfer(owner, balance), "Transfer failed");
        totalDeposits = 0;
        totalDebt = 0;
    }
}