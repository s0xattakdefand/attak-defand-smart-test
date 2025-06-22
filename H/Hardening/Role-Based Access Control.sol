// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract HardenedAccess is AccessControl {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    constructor(address admin) {
        _grantRole(ADMIN_ROLE, admin);
    }

    function criticalAction() external onlyRole(ADMIN_ROLE) {
        // Protected logic
    }
}
