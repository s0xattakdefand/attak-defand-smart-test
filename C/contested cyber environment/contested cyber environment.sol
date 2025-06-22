// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ContestedEnvResilienceGuard {
    address public admin;
    uint256 public constant MOE_THRESHOLD = 20; // e.g., drift level or block delay
    mapping(bytes32 => uint256) public driftReports;

    bool public emergencyMode;

    event DriftReported(bytes32 source, uint256 level, address reporter);
    event EmergencyTriggered();
    event EmergencyCleared();

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function reportDrift(bytes32 source, uint256 driftLevel) external {
        driftReports[source] = driftLevel;
        emit DriftReported(source, driftLevel, msg.sender);

        if (driftLevel >= MOE_THRESHOLD && !emergencyMode) {
            emergencyMode = true;
            emit EmergencyTriggered();
        }
    }

    function clearEmergency() external onlyAdmin {
        emergencyMode = false;
        emit EmergencyCleared();
    }

    function isOperational() external view returns (bool) {
        return !emergencyMode;
    }
}
