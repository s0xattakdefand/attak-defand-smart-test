// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Enhanced Secure Bank Contract
contract EnhancedSecureBank {
    mapping(address => uint256) public balances;
    bool private locked; // Reentrancy guard
    uint256 public constant MAX_WITHDRAWAL = 1 ether; // Limit per withdrawal
    address public owner; // Admin for emergency functions

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    event EmergencyStop(bool status);

    modifier nonReentrant() {
        require(!locked, "Reentrancy detected");
        locked = true;
        _;
        locked = false;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable nonReentrant {
        require(msg.value > 0, "Deposit must be > 0");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(amount > 0 && amount <= balances[msg.sender], "Invalid amount");
        require(amount <= MAX_WITHDRAWAL, "Exceeds max withdrawal limit");

        // Update state first (Effects before Interactions)
        balances[msg.sender] -= amount;
        emit Withdrawal(msg.sender, amount);

        // Gas-efficient transfer with error handling
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    function emergencyStop(bool stop) external onlyOwner {
        locked = stop; // Lock contract in emergency
        emit EmergencyStop(stop);
    }

    function getContractBalance() external view returns (uint256) {
        return address(this).balance;
    }

    // Allow owner to transfer ownership
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid address");
        owner = newOwner;
    }
}