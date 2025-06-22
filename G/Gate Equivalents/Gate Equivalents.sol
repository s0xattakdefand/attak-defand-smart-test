// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title GateEquivalentsAttackDefense - Full Attack and Defense Simulation for Gate Equivalents in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Contract (Minimized Gate Equivalents - Vulnerable to Validation Bypass)
contract InsecureGateEquivalent {
    mapping(address => uint256) public balances;

    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Not enough balance");
        // BAD: No reentrancy protection, no max withdrawal rate, no secondary checks
        balances[msg.sender] -= amount;

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Withdraw failed");

        emit Withdraw(msg.sender, amount);
    }
}

/// @notice Secure Contract (Proper Defense and Balanced Gate Equivalent Logic)
contract SecureGateEquivalent {
    mapping(address => uint256) public balances;
    uint256 public constant MAX_WITHDRAWAL_PER_TX = 10 ether;

    event SecureDeposit(address indexed user, uint256 amount);
    event SecureWithdraw(address indexed user, uint256 amount);

    bool private locked;

    modifier noReentrancy() {
        require(!locked, "Reentrancy attack blocked");
        locked = true;
        _;
        locked = false;
    }

    function deposit() external payable {
        require(msg.value > 0, "Deposit must be greater than zero");
        balances[msg.sender] += msg.value;
        emit SecureDeposit(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external noReentrancy {
        require(balances[msg.sender] >= amount, "Not enough balance");
        require(amount <= MAX_WITHDRAWAL_PER_TX, "Withdrawal exceeds limit");

        balances[msg.sender] -= amount;

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Withdraw failed");

        emit SecureWithdraw(msg.sender, amount);
    }

    function getBalance(address user) external view returns (uint256) {
        return balances[user];
    }
}

/// @notice Attack contract simulating gas grief and logic bypass
contract GateEquivalentIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function drain(address victim, uint256 amount) external {
        (bool success, ) = targetInsecure.call(
            abi.encodeWithSignature("withdraw(uint256)", amount)
        );
        require(success, "Attack failed");
    }
}
