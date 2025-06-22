// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract BlueTeamAccessControl is AccessControl {
    bytes32 public constant BLUE_TEAM_ROLE = keccak256("BLUE_TEAM_ROLE");

    event AlertHandled(address indexed analyst, string actionTaken);

    constructor() {
        // Grant the deployer the admin and blue team roles
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(BLUE_TEAM_ROLE, msg.sender);
    }

    /**
     * @notice Add a new blue team analyst.
     * @param analyst Address to be granted the BLUE_TEAM_ROLE.
     */
    function addBlueTeamMember(address analyst) public onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(BLUE_TEAM_ROLE, analyst);
    }

    /**
     * @notice Revoke blue team access.
     */
    function removeBlueTeamMember(address analyst) public onlyRole(DEFAULT_ADMIN_ROLE) {
        _revokeRole(BLUE_TEAM_ROLE, analyst);
    }

    /**
     * @notice Example function restricted to Blue Team members.
     */
    function respondToAlert(string calldata action) public onlyRole(BLUE_TEAM_ROLE) {
        emit AlertHandled(msg.sender, action);
    }
}
