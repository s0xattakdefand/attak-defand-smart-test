pragma solidity ^0.8.21;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract RoleRevoker is AccessControl {
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR");

    function revokeOperator(address user) external onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(OPERATOR_ROLE, user);
    }
}
