// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract AccessControlledConfig is AccessControl {
    bytes32 public constant CONFIG_ADMIN = keccak256("CONFIG_ADMIN");
    uint256 public param;

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(CONFIG_ADMIN, admin);
    }

    function setParam(uint256 newVal) external onlyRole(CONFIG_ADMIN) {
        param = newVal;
    }
}
