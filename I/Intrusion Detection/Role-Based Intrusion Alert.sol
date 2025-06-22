pragma solidity ^0.8.21;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract RoleBasedIDS is AccessControl {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    event UnauthorizedRoleAccess(address intruder, string action);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
    }

    function criticalFunction() external {
        if (!hasRole(ADMIN_ROLE, msg.sender)) {
            emit UnauthorizedRoleAccess(msg.sender, "criticalFunction");
            revert("Unauthorized");
        }
        // Critical logic
    }
}
