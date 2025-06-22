// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Active Attack Simulation & Defense

contract ActiveAttackProtectedVault {
    address public owner;
    mapping(address => uint256) public balances;
    mapping(address => uint256) public nonces;
    bool internal locked;

    event Deposit(address indexed from, uint256 amount);
    event Withdraw(address indexed to, uint256 amount);
    event AttackDetected(address indexed attacker, string reason);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier noReentrancy() {
        require(!locked, "Reentrancy detected");
        locked = true;
        _;
        locked = false;
    }

    constructor() {
        owner = msg.sender;
    }

    /// DEFENSE: Deposits tracked by user
    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /// DEFENSE: Only owner can withdraw with nonce + lock
    function withdraw(uint256 amount, uint256 nonce) external onlyOwner noReentrancy {
        require(nonces[msg.sender] == nonce, "Replay blocked");
        require(balances[msg.sender] >= amount, "Insufficient");
        
        nonces[msg.sender]++;
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);

        emit Withdraw(msg.sender, amount);
    }

    /// ATTACK: Simulate reentry or logic abuse
    function attack(uint256 fakeNonce) external {
        emit AttackDetected(msg.sender, "Simulated reentry or fake logic injection");
        revert("Active attack blocked");
    }

    /// View balance
    function getBalance(address user) external view returns (uint256) {
        return balances[user];
    }
}
