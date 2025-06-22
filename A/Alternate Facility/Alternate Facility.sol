// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";

interface IAlternateFacility {
    function executeBackupAction(address user, bytes calldata payload) external returns (bool);
}

contract AlternateFacilityFailover is AccessControl {
    bytes32 public constant FACILITY_ADMIN_ROLE = keccak256("FACILITY_ADMIN_ROLE");

    bool public primaryActive = true;
    address public alternateFacility;

    event PrimaryDeactivated(address by);
    event PrimaryReactivated(address by);
    event AlternateFacilitySet(address facility);
    event BackupExecuted(address indexed user, bytes payload);

    constructor(address _alternateFacility) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(FACILITY_ADMIN_ROLE, msg.sender);
        alternateFacility = _alternateFacility;
    }

    modifier onlyPrimaryActive() {
        require(primaryActive, "Primary is deactivated");
        _;
    }

    function executePrimaryAction(bytes calldata payload) external onlyPrimaryActive {
        // primary logic goes here (simulated by event or storage write)
        // e.g., withdraw, vote, etc.
    }

    function executeBackup(bytes calldata payload) external {
        require(!primaryActive, "Primary still active");
        require(alternateFacility != address(0), "No backup set");

        bool success = IAlternateFacility(alternateFacility).executeBackupAction(msg.sender, payload);
        require(success, "Backup execution failed");

        emit BackupExecuted(msg.sender, payload);
    }

    function deactivatePrimary() external onlyRole(FACILITY_ADMIN_ROLE) {
        primaryActive = false;
        emit PrimaryDeactivated(msg.sender);
    }

    function reactivatePrimary() external onlyRole(FACILITY_ADMIN_ROLE) {
        primaryActive = true;
        emit PrimaryReactivated(msg.sender);
    }

    function setAlternateFacility(address newFacility) external onlyRole(DEFAULT_ADMIN_ROLE) {
        alternateFacility = newFacility;
        emit AlternateFacilitySet(newFacility);
    }
}
