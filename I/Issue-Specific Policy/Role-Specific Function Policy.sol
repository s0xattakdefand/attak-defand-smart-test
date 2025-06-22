pragma solidity ^0.8.21;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract RolePolicy is AccessControl {
    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function auditLogs() external view onlyRole(AUDITOR_ROLE) returns (string memory) {
        return "Logs available to auditors only";
    }
}
