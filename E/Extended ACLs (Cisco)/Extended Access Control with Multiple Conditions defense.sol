// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * DEFENSE TYPE:
 * We do advanced access checks like: 
 * - Role-based from AccessControl
 * - Condition on function param
 * - Possibly time-based or multi-sig approach
 */
import "@openzeppelin/contracts/access/AccessControl.sol";

contract ExtendedACLContract is AccessControl {
    bytes32 public constant EDITOR_ROLE = keccak256("EDITOR_ROLE");
    uint256 public data;
    uint256 public lastUpdate;

    constructor(address admin, address editor) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(EDITOR_ROLE, editor);
    }

    /**
     * @dev Only addresses with EDITOR_ROLE can call, 
     * plus we do an extra condition, e.g. only certain time range or param check.
     */
    function updateData(uint256 newData) external onlyRole(EDITOR_ROLE) {
        require(newData < 10000, "Data must be < 10000"); // extended condition
        require(block.timestamp > lastUpdate + 60, "Wait 60s before next update"); // time-based check
        data = newData;
        lastUpdate = block.timestamp;
    }
}
