pragma solidity ^0.8.21;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract IntranetSecureContract is AccessControl {
    bytes32 public constant INTERNAL_ROLE = keccak256("INTERNAL_ROLE");
    string private confidentialData;

    event ConfidentialActionPerformed(address executor);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    function grantInternalAccess(address user) external onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(INTERNAL_ROLE, user);
    }

    function revokeInternalAccess(address user) external onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(INTERNAL_ROLE, user);
    }

    function confidentialAction(string memory data) external onlyRole(INTERNAL_ROLE) {
        confidentialData = data;
        emit ConfidentialActionPerformed(msg.sender);
    }

    function viewConfidentialData() external view onlyRole(INTERNAL_ROLE) returns (string memory) {
        return confidentialData;
    }
}
