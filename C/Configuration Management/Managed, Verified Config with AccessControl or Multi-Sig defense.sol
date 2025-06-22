// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * DEFENSE TYPE:
 * - Use an admin role for config changes
 * - Possibly a multi-sig or at least different from dev test address
 */
contract SecureConfig is AccessControl {
    bytes32 public constant CONFIG_ADMIN = keccak256("CONFIG_ADMIN");
    uint256 public feeRate;

    constructor(address configAdmin) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(CONFIG_ADMIN, configAdmin);
    }

    function setFeeRate(uint256 newFee) external onlyRole(CONFIG_ADMIN) {
        // validated approach, no leftover test addresses
        feeRate = newFee;
    }

    function getFeeRate() external view returns (uint256) {
        return feeRate;
    }
}
