// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

/// @title BaselineEnforcedContract — Demonstrates a secure control baseline
contract BaselineEnforcedContract is Ownable, Pausable, UUPSUpgradeable {
    mapping(address => bool) public operators;

    event OperatorAdded(address indexed user);
    event OperatorRemoved(address indexed user);
    event ActionExecuted(address indexed operator, string details);

    modifier onlyOperator() {
        require(operators[msg.sender], "Not operator");
        _;
    }

    /// ✅ Baseline: Controlled Operator Role Management
    function addOperator(address user) external onlyOwner {
        operators[user] = true;
        emit OperatorAdded(user);
    }

    function removeOperator(address user) external onlyOwner {
        operators[user] = false;
        emit OperatorRemoved(user);
    }

    /// ✅ Baseline: Status-Enforced Execution
    function performAction(string calldata description) external onlyOperator whenNotPaused {
        emit ActionExecuted(msg.sender, description);
    }

    /// ✅ Baseline: Emergency Pause Mechanism
    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    /// ✅ Baseline: Upgrade Authorization Control
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
