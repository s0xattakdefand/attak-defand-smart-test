// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * A naive contract that never stores backups or data to a DR site.
 * Attack scenario: If main net or contract state is corrupted,
 * there's no fallback => total data loss or indefinite downtime
 */
contract NaiveNoDR {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
    
    // ❌ No backups, no fallback site => Attackers or chain meltdown => data or funds locked forever
}
