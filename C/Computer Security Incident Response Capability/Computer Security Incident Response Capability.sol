// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CSIRCResponseController {
    address public owner;
    mapping(address => bool) public certMember;
    mapping(address => bool) public blacklisted;
    bool public emergencyPaused;

    enum Severity { Low, Medium, High, Critical }

    struct Incident {
        address reporter;
        address suspect;
        string category;
        Severity severity;
        uint256 timestamp;
        bool mitigated;
    }

    Incident[] public incidents;

    event IncidentReported(address indexed reporter, address indexed suspect, string category, Severity severity);
    event SystemPaused(address indexed by);
    event SystemUnpaused(address indexed by);
    event AddressBlacklisted(address indexed actor);
    event AddressCleared(address indexed actor);

    modifier onlyCERT() {
        require(certMember[msg.sender], "Not CERT");
        _;
    }

    constructor() {
        owner = msg.sender;
        certMember[msg.sender] = true;
    }

    function reportIncident(address suspect, string calldata category, Severity severity) external onlyCERT {
        incidents.push(Incident({
            reporter: msg.sender,
            suspect: suspect,
            category: category,
            severity: severity,
            timestamp: block.timestamp,
            mitigated: false
        }));

        emit IncidentReported(msg.sender, suspect, category, severity);

        if (severity == Severity.Critical) {
            emergencyPaused = true;
            emit SystemPaused(msg.sender);
        }
    }

    function pauseSystem() external onlyCERT {
        emergencyPaused = true;
        emit SystemPaused(msg.sender);
    }

    function unpauseSystem() external onlyCERT {
        emergencyPaused = false;
        emit SystemUnpaused(msg.sender);
    }

    function blacklist(address attacker) external onlyCERT {
        blacklisted[attacker] = true;
        emit AddressBlacklisted(attacker);
    }

    function clearBlacklist(address addr) external onlyCERT {
        blacklisted[addr] = false;
        emit AddressCleared(addr);
    }

    function addCERT(address member) external {
        require(msg.sender == owner, "Not owner");
        certMember[member] = true;
    }

    function removeCERT(address member) external {
        require(msg.sender == owner, "Not owner");
        certMember[member] = false;
    }

    function getIncident(uint256 index) external view returns (Incident memory) {
        return incidents[index];
    }

    function totalIncidents() external view returns (uint256) {
        return incidents.length;
    }
}
