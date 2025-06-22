// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Admin Incident Handler and Monitor
contract AdminIncidentMonitor {
    address public admin;
    bool public paused;
    uint256 public incidentCounter;

    struct Incident {
        uint256 id;
        address triggeredBy;
        string reason;
        uint256 timestamp;
        bool acknowledged;
    }

    mapping(uint256 => Incident) public incidents;

    event IncidentReported(uint256 indexed id, address indexed by, string reason);
    event SystemPaused();
    event IncidentAcknowledged(uint256 indexed id, address indexed by);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier notPaused() {
        require(!paused, "System paused due to incident");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function reportIncident(string calldata reason) external returns (uint256 id) {
        id = ++incidentCounter;
        incidents[id] = Incident(id, msg.sender, reason, block.timestamp, false);
        paused = true;
        emit IncidentReported(id, msg.sender, reason);
        emit SystemPaused();
    }

    function acknowledgeIncident(uint256 id) external onlyAdmin {
        require(!incidents[id].acknowledged, "Already acknowledged");
        incidents[id].acknowledged = true;
        emit IncidentAcknowledged(id, msg.sender);
    }

    function resumeSystem() external onlyAdmin {
        paused = false;
    }

    function getIncident(uint256 id) external view returns (Incident memory) {
        return incidents[id];
    }
}
