// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract ComplexConditionACL is AccessControl {
    bytes32 public constant CONTROLLER_ROLE = keccak256("CONTROLLER_ROLE");
    IERC20 public token;
    uint256 public threshold;

    constructor(address admin, address tokenAddress, uint256 balanceThreshold) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(CONTROLLER_ROLE, admin);
        token = IERC20(tokenAddress);
        threshold = balanceThreshold;
    }

    function sensitiveAction(uint256 param) external onlyRole(CONTROLLER_ROLE) {
        // Additional condition: caller must hold >= threshold tokens
        require(token.balanceOf(msg.sender) >= threshold, "Not enough token balance");
        // Also param must be < 500
        require(param < 500, "Param too large");

        // do the action
    }
}
