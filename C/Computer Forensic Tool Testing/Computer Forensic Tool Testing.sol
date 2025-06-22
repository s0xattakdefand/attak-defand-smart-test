// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ForensicToolTestHarness {
    address public admin;
    mapping(address => bool) public canExploit;
    bool public locked;
    uint256 public counter;

    event ForensicStep(string action, address actor, uint256 gasRemaining);
    event PotentialExploit(address indexed attacker, string typeOf);

    modifier noReentrancy() {
        require(!locked, "Reentrant");
        locked = true;
        _;
        locked = false;
    }

    constructor() {
        admin = msg.sender;
    }

    function triggerReentrancy() external noReentrancy {
        emit ForensicStep("EnterReentrancy", msg.sender, gasleft());

        if (canExploit[msg.sender]) {
            emit PotentialExploit(msg.sender, "Reentrancy");
            this.triggerReentrancy(); // Simulated reentrancy loop
        }

        emit ForensicStep("ExitReentrancy", msg.sender, gasleft());
    }

    function enableExploit(address attacker) external {
        require(msg.sender == admin, "Not admin");
        canExploit[attacker] = true;
    }

    function spoofBackdoor() external {
        emit ForensicStep("BackdoorAccess", msg.sender, gasleft());
        if (msg.sender == tx.origin) {
            emit PotentialExploit(msg.sender, "BackdoorRoleEscalation");
        }
    }

    function simulateGasLoop() external {
        for (uint256 i = 0; i < 100; i++) {
            emit ForensicStep("GasSinkIteration", msg.sender, gasleft());
        }
    }
}
