pragma solidity ^0.8.21;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract RBACKernel is AccessControl {
    bytes32 public constant EXEC_ROLE = keccak256("EXEC_ROLE");

    function runCommand() external onlyRole(EXEC_ROLE) {
        // Only execs can perform this
    }
}
