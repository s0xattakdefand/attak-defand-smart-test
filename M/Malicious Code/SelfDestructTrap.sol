// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @title SelfDestructTrap - Anyone can trigger it
contract SelfDestructTrap {
    string public info = "Totally safe contract...";

    function nuke() external {
        selfdestruct(payable(msg.sender)); // 💣 Trap
    }
}
