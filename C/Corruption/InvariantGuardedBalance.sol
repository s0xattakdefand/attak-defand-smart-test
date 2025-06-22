// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract InvariantGuardedBalance {
    mapping(address => uint256) private balances;
    uint256 private total;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        total += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Too much");
        balances[msg.sender] -= amount;
        total -= amount;
        payable(msg.sender).transfer(amount);
    }

    function invariantCheck() external view returns (bool) {
        return address(this).balance == total;
    }
}
