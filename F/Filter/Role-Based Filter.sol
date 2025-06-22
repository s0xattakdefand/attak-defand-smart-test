// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract RoleFilter is AccessControl {
    bytes32 public constant FILTERED_ROLE = keccak256("FILTERED_ROLE");

    uint256 public value;

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(FILTERED_ROLE, admin);
    }

    function setValue(uint256 newValue) external onlyRole(FILTERED_ROLE) {
        value = newValue;
    }
}
