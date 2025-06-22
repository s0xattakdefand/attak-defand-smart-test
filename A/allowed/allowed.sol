// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract AllowanceManager is AccessControl {
    bytes32 public constant ALLOWANCE_ADMIN_ROLE = keccak256("ALLOWANCE_ADMIN_ROLE");

    mapping(address => bool) public allowedAddresses;

    event AddressAllowed(address indexed addr);
    event AddressDisallowed(address indexed addr);
    event ActionExecuted(address indexed user, string action);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ALLOWANCE_ADMIN_ROLE, msg.sender);
    }

    modifier onlyAllowed() {
        require(allowedAddresses[msg.sender], "Address not allowed");
        _;
    }

    /// @notice Authorize address dynamically
    function allowAddress(address addr) external onlyRole(ALLOWANCE_ADMIN_ROLE) {
        allowedAddresses[addr] = true;
        emit AddressAllowed(addr);
    }

    /// @notice Revoke authorization dynamically
    function disallowAddress(address addr) external onlyRole(ALLOWANCE_ADMIN_ROLE) {
        allowedAddresses[addr] = false;
        emit AddressDisallowed(addr);
    }

    /// @notice Check allowance dynamically
    function isAllowed(address addr) external view returns (bool) {
        return allowedAddresses[addr];
    }

    /// @notice Execute an allowed-only action securely
    function executeAllowedAction(string calldata actionDetails) external onlyAllowed {
        require(bytes(actionDetails).length > 0, "Action details required");

        emit ActionExecuted(msg.sender, actionDetails);
        // Secure action logic here
    }
}
