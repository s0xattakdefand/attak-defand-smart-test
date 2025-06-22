// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

/// @title ModularControlSystem — A full control system combining roles, pause, and upgrade protections
contract ModularControlSystem is AccessControl, Pausable, UUPSUpgradeable {
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    event ActionExecuted(string action, address indexed operator);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);
    }

    /// 🔐 Enforced Action
    function executeAction(string calldata label)
        external
        onlyRole(OPERATOR_ROLE)
        whenNotPaused
        returns (string memory)
    {
        emit ActionExecuted(label, msg.sender);
        return string(abi.encodePacked("Executed: ", label));
    }

    /// 🛑 Pause / Unpause
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// 🔁 Secure Upgrade Authorization
    function _authorizeUpgrade(address newImplementation)
        internal
        override
        onlyRole(UPGRADER_ROLE)
    {}
}
