pragma solidity ^0.8.21;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract InterruptResistantContract is ReentrancyGuard {
    uint256 public totalDeposits;
    mapping(address => uint256) public balances;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        balances[msg.sender] -= amount;
        totalDeposits -= amount;

        (bool success,) = payable(msg.sender).call{value: amount, gas: 2300}("");
        require(success, "Withdrawal interrupted");

        emit Withdrawn(msg.sender, amount);
    }
}
