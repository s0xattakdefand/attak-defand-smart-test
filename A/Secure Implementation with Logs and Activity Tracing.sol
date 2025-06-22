// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ActivityMonitoring {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public failedAttempts;

    event TransferPerformed(address indexed from, address indexed to, uint256 amount);
    event AdminWithdraw(address indexed admin, uint256 amount);
    event UnauthorizedAccessAttempt(address indexed caller, string functionName);
    event SuspiciousActivityDetected(address indexed caller, uint256 timestamp);

    constructor() {
        owner = msg.sender;
        balances[msg.sender] = 100 ether;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) {
            failedAttempts += 1;
            emit UnauthorizedAccessAttempt(msg.sender, "onlyOwner()");
            if (failedAttempts >= 3) {
                emit SuspiciousActivityDetected(msg.sender, block.timestamp);
            }
            revert("Unauthorized");
        }
        _;
    }

    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient funds");
        balances[msg.sender] -= amount;
        balances[to] += amount;

        emit TransferPerformed(msg.sender, to, amount);
    }

    function adminWithdraw(uint256 amount) public onlyOwner {
        balances[msg.sender] += amount;
        emit AdminWithdraw(msg.sender, amount);
    }
}
