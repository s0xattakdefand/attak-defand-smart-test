// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract SecurityIncidentLogger {
    address public owner;
    bool public systemPaused;

    enum Severity { Low, Medium, High, Critical }

    struct Incident {
        address reporter;
        string category;
        string description;
        Severity severity;
        uint256 timestamp;
        bool mitigated;
    }

    Incident[] public incidents;

    event IncidentReported(
        address indexed reporter,
        string category,
        Severity severity,
        string description
    );

    event SystemPaused(address by);
    event SystemResumed(address by);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    modifier notPaused() {
        require(!systemPaused, "System paused due to incident");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function reportIncident(
        string calldata category,
        string calldata description,
        Severity severity
    ) external {
        incidents.push(Incident({
            reporter: msg.sender,
            category: category,
            description: description,
            severity: severity,
            timestamp: block.timestamp,
            mitigated: false
        }));

        emit IncidentReported(msg.sender, category, severity, description);

        // Auto-pause if critical
        if (severity == Severity.Critical) {
            systemPaused = true;
            emit SystemPaused(msg.sender);
        }
    }

    function markMitigated(uint256 id) external onlyOwner {
        incidents[id].mitigated = true;
    }

    function resumeSystem() external onlyOwner {
        systemPaused = false;
        emit SystemResumed(msg.sender);
    }

    function getIncidentCount() external view returns (uint256) {
        return incidents.length;
    }
}
