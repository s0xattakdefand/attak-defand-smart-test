// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title ControlledAreaVault — High-security controlled area example
contract ControlledAreaVault is AccessControl, Pausable {
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    IERC20 public acceptedToken;
    address public treasury;

    event VaultAccessGranted(address indexed user, uint256 amount);
    event EmergencyPauseActivated(address indexed by);
    event TokenWithdrawn(address indexed to, uint256 amount);

    constructor(address admin, address token, address treasuryAddr) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, admin);
        acceptedToken = IERC20(token);
        treasury = treasuryAddr;
    }

    /// 🛡️ Controlled access function
    function requestAccess(uint256 amount)
        external
        whenNotPaused
    {
        require(acceptedToken.balanceOf(msg.sender) >= amount, "Insufficient tokens for access");
        emit VaultAccessGranted(msg.sender, amount);
        // Perform gated logic here (e.g., issue NFT, reveal data, etc.)
    }

    /// 🔒 Admin-only token withdrawal
    function withdraw(uint256 amount)
        external
        onlyRole(GUARDIAN_ROLE)
    {
        acceptedToken.transfer(treasury, amount);
        emit TokenWithdrawn(treasury, amount);
    }

    /// 🚨 Emergency pause
    function triggerEmergency()
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        _pause();
        emit EmergencyPauseActivated(msg.sender);
    }

    function liftEmergency()
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        _unpause();
    }
}
