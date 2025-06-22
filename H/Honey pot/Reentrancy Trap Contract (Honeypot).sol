// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ReentrancyTrap {
    mapping(address => uint256) public balances;
    bool public trapSprung;

    event AttackerTrapped(address attacker);

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        if (gasleft() > 100_000) {
            trapSprung = true;
            emit AttackerTrapped(msg.sender);
            revert("Caught you, reentrancy bot!");
        }

        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
}
