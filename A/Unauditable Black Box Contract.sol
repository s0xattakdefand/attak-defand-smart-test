// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract UnauditableBank {
    mapping(address => uint256) private balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
        // ❌ No logs, no visibility, no audit trail
    }

    function emergencyDrain(address to) public {
        payable(to).transfer(address(this).balance);
        // ❌ No access control, no event emitted
    }
}
