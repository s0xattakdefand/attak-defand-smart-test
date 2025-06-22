// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CAPECRegistry {
    address public admin;

    enum Status { Undetected, Detected, Mitigated }
    enum Vector { Storage, Logic, AccessControl, Oracle, Tokenomics }

    struct AttackPattern {
        string name;
        string description;
        uint16 capecId;
        Vector vector;
        Status status;
        uint8 severity; // 1 (low) - 5 (critical)
        uint256 timestamp;
    }

    mapping(uint16 => AttackPattern) public patterns;
    uint16[] public patternIds;

    event AttackRegistered(uint16 indexed capecId, string name, Vector vector, uint8 severity);
    event StatusUpdated(uint16 indexed capecId, Status status);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerAttack(
        uint16 capecId,
        string calldata name,
        string calldata description,
        Vector vector,
        uint8 severity
    ) external onlyAdmin {
        require(patterns[capecId].timestamp == 0, "Already registered");
        require(severity >= 1 && severity <= 5, "Severity out of range");

        patterns[capecId] = AttackPattern({
            name: name,
            description: description,
            capecId: capecId,
            vector: vector,
            status: Status.Undetected,
            severity: severity,
            timestamp: block.timestamp
        });

        patternIds.push(capecId);
        emit AttackRegistered(capecId, name, vector, severity);
    }

    function updateStatus(uint16 capecId, Status newStatus) external onlyAdmin {
        require(patterns[capecId].timestamp > 0, "Not found");
        patterns[capecId].status = newStatus;
        emit StatusUpdated(capecId, newStatus);
    }

    function getPattern(uint16 capecId) external view returns (
        string memory name,
        string memory description,
        Vector vector,
        Status status,
        uint8 severity,
        uint256 timestamp
    ) {
        AttackPattern memory p = patterns[capecId];
        return (p.name, p.description, p.vector, p.status, p.severity, p.timestamp);
    }

    function getAllPatternIds() external view returns (uint16[] memory) {
        return patternIds;
    }
}
