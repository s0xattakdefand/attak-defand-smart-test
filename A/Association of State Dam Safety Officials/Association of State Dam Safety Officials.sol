// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title InfrastructureRiskRegistry - Web3 adaptation of ASDSO for critical protocol safety oversight

contract InfrastructureRiskRegistry {
    address public regulator;

    enum RiskLevel { Low, Moderate, High, Critical }

    struct Infrastructure {
        string name;
        address contractAddress;
        RiskLevel riskLevel;
        bool accredited;
        uint256 lastInspection;
        string notes;
    }

    mapping(uint256 => Infrastructure) public registry;
    uint256 public infraCount;

    event Registered(uint256 indexed id, string name, RiskLevel riskLevel);
    event Inspected(uint256 indexed id, RiskLevel newRiskLevel, string notes);
    event EmergencyFlagged(uint256 indexed id, string reason);
    event AccreditationUpdated(uint256 indexed id, bool status);

    modifier onlyRegulator() {
        require(msg.sender == regulator, "Not regulator");
        _;
    }

    constructor() {
        regulator = msg.sender;
    }

    function registerInfra(
        string calldata name,
        address contractAddress,
        RiskLevel initialLevel,
        string calldata notes
    ) external onlyRegulator returns (uint256 id) {
        id = ++infraCount;
        registry[id] = Infrastructure({
            name: name,
            contractAddress: contractAddress,
            riskLevel: initialLevel,
            accredited: false,
            lastInspection: block.timestamp,
            notes: notes
        });
        emit Registered(id, name, initialLevel);
    }

    function inspectInfra(
        uint256 id,
        RiskLevel newLevel,
        string calldata notes
    ) external onlyRegulator {
        Infrastructure storage infra = registry[id];
        infra.riskLevel = newLevel;
        infra.lastInspection = block.timestamp;
        infra.notes = notes;
        emit Inspected(id, newLevel, notes);
    }

    function flagEmergency(uint256 id, string calldata reason) external onlyRegulator {
        emit EmergencyFlagged(id, reason);
    }

    function setAccreditation(uint256 id, bool status) external onlyRegulator {
        registry[id].accredited = status;
        emit AccreditationUpdated(id, status);
    }

    function getInfra(uint256 id) external view returns (Infrastructure memory) {
        return registry[id];
    }
}
