// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract ContingencyKeyManager is AccessControl {
    bytes32 public constant CONTINGENCY_ROLE = keccak256("CONTINGENCY_ROLE");

    uint256 public constant ACTIVATION_DELAY = 2 days;
    mapping(address => uint256) public requestedActivation;

    event ContingencyActivationRequested(address key, uint256 at);
    event ContingencyActivated(address key);

    constructor(address admin, address contingencyKey) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _setupRole(CONTINGENCY_ROLE, contingencyKey);
        _revokeRole(CONTINGENCY_ROLE, contingencyKey); // Delay required
    }

    function requestActivation(address contingencyKey) external onlyRole(DEFAULT_ADMIN_ROLE) {
        requestedActivation[contingencyKey] = block.timestamp + ACTIVATION_DELAY;
        emit ContingencyActivationRequested(contingencyKey, requestedActivation[contingencyKey]);
    }

    function activateContingencyKey(address contingencyKey) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(block.timestamp >= requestedActivation[contingencyKey], "Delay not passed");
        _grantRole(CONTINGENCY_ROLE, contingencyKey);
        emit ContingencyActivated(contingencyKey);
    }

    function executeEmergency(address target, bytes calldata data) external onlyRole(CONTINGENCY_ROLE) {
        (bool success, ) = target.call(data);
        require(success, "Contingency call failed");
    }
}
