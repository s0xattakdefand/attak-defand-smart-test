// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract WormGuard {
    mapping(address => bool) public quarantined;

    function quarantine(address target) external {
        quarantined[target] = true;
    }

    modifier notWormed() {
        require(!quarantined[msg.sender], "Worm detected");
        _;
    }

    function safeWithdraw() external notWormed {
        // legitimate logic
    }
}
