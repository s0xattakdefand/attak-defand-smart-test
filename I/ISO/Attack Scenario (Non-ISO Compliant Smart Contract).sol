// Vulnerable: no access control, logging, or validation
pragma solidity ^0.8.21;

contract UnsecuredTransfer {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function transfer(address to, uint256 amount) external {
        balances[msg.sender] -= amount; // No validation!
        balances[to] += amount;
    }
}
