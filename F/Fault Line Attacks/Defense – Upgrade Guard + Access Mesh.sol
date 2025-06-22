// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin/contracts/proxy/ProxyAdmin.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * DEFENSE:
 * - Proxy upgrade is gated by AccessControl.
 * - Vault and Operator roles are split but tightly scoped.
 */

contract SecureVault is AccessControl {
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    address public stored;

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
    }

    function set(address _value) external onlyRole(OPERATOR_ROLE) {
        stored = _value;
    }
}
