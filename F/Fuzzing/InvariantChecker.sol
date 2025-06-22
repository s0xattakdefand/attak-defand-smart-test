// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract InvariantChecker {
    mapping(address => uint256) public balances;
    uint256 public total;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        total += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        total -= amount;
        payable(msg.sender).transfer(amount);
    }

    function invariant() external view returns (bool) {
        return address(this).balance == total;
    }
}
