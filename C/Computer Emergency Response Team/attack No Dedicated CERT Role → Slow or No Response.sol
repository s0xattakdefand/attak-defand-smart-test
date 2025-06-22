// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Attack scenario:
 * A naive contract with no dedicated emergency response team or function.
 * If exploited, there's no quick way to halt or mitigate damage.
 */
contract NaiveNoCERT {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        // ❌ If there's a reentrancy or logic bug, no quick fix or pause
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
