// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

contract ConsequenceResilienceGuard is Pausable, AccessControl {
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    uint256 public constant MAX_WITHDRAW = 100 ether;
    bool public adminFinalized;

    mapping(address => uint256) public withdrawn;

    event KillSwitchActivated(address by);
    event AdminFinalized();

    constructor() {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setupRole(GUARDIAN_ROLE, msg.sender);
    }

    function withdraw(address to, uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE) whenNotPaused {
        require(amount <= MAX_WITHDRAW, "Exceeds per-call limit");
        withdrawn[to] += amount;
        payable(to).transfer(amount);
    }

    function killSwitch() external onlyRole(GUARDIAN_ROLE) {
        _pause();
        emit KillSwitchActivated(msg.sender);
    }

    function finalizeAdmin() external onlyRole(DEFAULT_ADMIN_ROLE) {
        adminFinalized = true;
        renounceRole(DEFAULT_ADMIN_ROLE, msg.sender);
        emit AdminFinalized();
    }

    receive() external payable {}
}
