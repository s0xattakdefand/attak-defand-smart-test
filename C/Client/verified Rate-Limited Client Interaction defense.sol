// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * A secure approach:
 * - Only recognized (role-based) clients can call 'processAction'
 * - Optional fee or rate-limiting to deter spam
 */
contract ClientDefense is AccessControl {
    bytes32 public constant APPROVED_CLIENT = keccak256("APPROVED_CLIENT");

    uint256 public actionCount;
    uint256 public callFee = 0.01 ether;

    constructor(address admin) {
        // Instead of _setupRole, we use _grantRole
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    function setCallFee(uint256 fee) external onlyRole(DEFAULT_ADMIN_ROLE) {
        callFee = fee;
    }

    // Only whitelisted (APPROVED_CLIENT) can call, must pay fee
    function processAction() external payable onlyRole(APPROVED_CLIENT) {
        require(msg.value >= callFee, "Insufficient call fee");
        actionCount++;
    }

    // Admin can add or remove clients
    function addClient(address client) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(APPROVED_CLIENT, client);
    }

    function removeClient(address client) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _revokeRole(APPROVED_CLIENT, client);
    }
}
