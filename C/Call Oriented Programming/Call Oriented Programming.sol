// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract COPDefense {
    address public admin;
    uint256 public totalBalance;

    mapping(address => uint256) public balances;
    bool private locked;

    event Deposit(address indexed depositor, uint256 amount);
    event Withdrawal(address indexed withdrawer, uint256 amount);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Unauthorized: Admin only");
        _;
    }

    modifier nonReentrant() {
        require(!locked, "Reentrancy detected");
        locked = true;
        _;
        locked = false;
    }

    constructor() {
        admin = msg.sender;
        locked = false;
    }

    // Safe deposit function
    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalBalance += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // Secure withdrawal with Checks-Effects-Interactions and Reentrancy Guard
    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient funds");

        // Checks & Effects
        balances[msg.sender] -= amount;
        totalBalance -= amount;

        // Interactions
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Withdrawal failed");

        emit Withdrawal(msg.sender, amount);
    }

    // Strict control on delegatecall usage
    function safeDelegateCall(address target, bytes calldata data) external onlyAdmin returns (bytes memory) {
        require(target != address(0), "Invalid target address");

        (bool success, bytes memory result) = target.delegatecall(data);
        require(success, "Delegatecall failed");

        return result;
    }

    // View balance
    function getBalance(address account) external view returns (uint256) {
        return balances[account];
    }
}
