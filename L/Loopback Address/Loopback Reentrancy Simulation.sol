// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @title LoopbackReentrancySim - Simulates reentrancy via loopback call
contract LoopbackReentrancySim {
    mapping(address => uint256) public balances;
    bool internal locked;

    constructor() payable {
        balances[msg.sender] = msg.value;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        require(!locked, "Reentrancy blocked");
        require(balances[msg.sender] >= 1 ether, "Insufficient");

        locked = true;

        // 🧨 Loopback call to itself
        (bool success, ) = address(this).call(
            abi.encodeWithSignature("finalizeWithdrawal(address)", msg.sender)
        );
        require(success, "Loopback call failed");

        locked = false;
    }

    function finalizeWithdrawal(address user) external {
        require(msg.sender == address(this), "Only self-call allowed");
        uint256 amount = balances[user];
        balances[user] = 0;
        payable(user).transfer(amount);
    }

    receive() external payable {}
}
