// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * Another approach: 
 * we keep a function 'public', but restrict it with AccessControl or onlyOwner, 
 * effectively encapsulating usage behind role checks.
 */
contract AccessControlEncapsulation is AccessControl {
    bytes32 public constant CONTROLLER_ROLE = keccak256("CONTROLLER_ROLE");

    uint256 public totalValue;

    constructor(address controller) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(CONTROLLER_ROLE, controller);
    }

    function addValue(uint256 val) public onlyRole(CONTROLLER_ROLE) {
        // We can keep it 'public', but only 'CONTROLLER_ROLE' can call
        totalValue += val;
    }

    function increment() external onlyRole(CONTROLLER_ROLE) {
        addValue(1);
    }
}
