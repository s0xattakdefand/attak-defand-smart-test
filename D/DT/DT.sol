// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title RoleController
 * @dev Contract for managing roles in the DT system.
 */
contract RoleController is AccessControl {
    bytes32 public constant ASSET_PROVIDER_ROLE = keccak256("ASSET_PROVIDER_ROLE");
    bytes32 public constant OP_TEMPLATE_ROLE = keccak256("OP_TEMPLATE_ROLE");
    bytes32 public constant DT_FACTORY_ROLE = keccak256("DT_FACTORY_ROLE");
    bytes32 public constant TASK_MARKET_ROLE = keccak256("TASK_MARKET_ROLE");

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function grantAssetProviderRole(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(ASSET_PROVIDER_ROLE, account);
    }

    function grantOpTemplateRole(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(OP_TEMPLATE_ROLE, account);
    }

    function grantDtFactoryRole(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(DT_FACTORY_ROLE, account);
    }

    function grantTaskMarketRole(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(TASK_MARKET_ROLE, account);
    }

    function revokeRoleFrom(address account, bytes32 role) external onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(role, account);
    }
}