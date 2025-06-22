// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title ControlledAccessArea — A vault-like area with multi-condition gated access
contract ControlledAccessArea is AccessControl {
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    IERC20 public accessToken;
    uint256 public unlockTime;

    event AccessGranted(address indexed user, string reason);
    event ProtectedActionExecuted(address indexed user);

    constructor(address token, uint256 delaySeconds, address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, admin);
        accessToken = IERC20(token);
        unlockTime = block.timestamp + delaySeconds;
    }

    modifier onlyWhenUnlocked() {
        require(block.timestamp >= unlockTime, "Controlled area is locked");
        _;
    }

    modifier tokenHolderOnly() {
        require(accessToken.balanceOf(msg.sender) > 0, "Access denied: no token");
        _;
    }

    modifier onlyGuardian() {
        require(hasRole(GUARDIAN_ROLE, msg.sender), "Access denied: not guardian");
        _;
    }

    // ✅ Protected vault action with full access gating
    function performProtectedAction()
        external
        onlyGuardian
        onlyWhenUnlocked
        tokenHolderOnly
    {
        emit ProtectedActionExecuted(msg.sender);
        // Critical vault or config logic here...
    }

    function grantAccessLog(string calldata reason) external {
        emit AccessGranted(msg.sender, reason);
    }

    // Admin can delay or accelerate unlock
    function setUnlockTime(uint256 newTime) external onlyRole(DEFAULT_ADMIN_ROLE) {
        unlockTime = newTime;
    }
}
