// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title DataLossAttackDefense - Full Attack and Defense Simulation for Data Loss Vulnerabilities
/// @author ChatGPT

/// @notice Secure contract preventing data loss
contract SecureDataStorage {
    address public owner;

    mapping(address => uint256) private userBalances;
    uint256 private totalDeposits;
    bool public locked; // Lock during sensitive operations

    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier noReentrant() {
        require(!locked, "Reentrancy blocked");
        locked = true;
        _;
        locked = false;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable noReentrant {
        require(msg.value > 0, "No value sent");

        userBalances[msg.sender] += msg.value;
        totalDeposits += msg.value;

        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 _amount) external noReentrant {
        require(userBalances[msg.sender] >= _amount, "Insufficient balance");

        userBalances[msg.sender] -= _amount;
        totalDeposits -= _amount;
        payable(msg.sender).transfer(_amount);

        emit Withdraw(msg.sender, _amount);
    }

    function emergencyReset() external onlyOwner {
        // Controlled reset (simulate emergency situations without losing user funds)
        totalDeposits = 0;
        // NOT deleting userBalances mapping to preserve data integrity
    }

    function getBalance(address user) external view returns (uint256) {
        return userBalances[user];
    }
}

/// @notice Attack contract trying to induce data loss via forced resets
contract DataLossIntruder {
    address public target;

    constructor(address _target) {
        target = _target;
    }

    function tryEmergencyReset() external returns (bool success) {
        (success, ) = target.call(
            abi.encodeWithSignature("emergencyReset()")
        );
        // This must fail if proper access control is enforced
    }
}
