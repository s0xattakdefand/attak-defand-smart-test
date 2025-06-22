// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AuditableBank {
    address public owner;
    mapping(address => uint256) private balances;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event EmergencyDrain(address indexed by, address to, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
        emit Withdrawn(msg.sender, amount);
    }

    function getBalance(address user) public view returns (uint256) {
        return balances[user];
    }

    function emergencyDrain(address to) public onlyOwner {
        uint256 total = address(this).balance;
        payable(to).transfer(total);
        emit EmergencyDrain(msg.sender, to, total);
    }

    receive() external payable {
        deposit();
    }
}
