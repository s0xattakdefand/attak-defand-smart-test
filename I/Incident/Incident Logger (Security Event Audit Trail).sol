// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract IncidentLogger {
    enum Severity { Info, Warning, Critical }

    struct Incident {
        address reporter;
        string description;
        Severity level;
        uint256 timestamp;
    }

    Incident[] public incidents;

    event IncidentReported(address reporter, Severity level, string description);

    function report(string calldata desc, Severity level) external {
        incidents.push(Incident({
            reporter: msg.sender,
            description: desc,
            level: level,
            timestamp: block.timestamp
        }));

        emit IncidentReported(msg.sender, level, desc);
    }

    function totalIncidents() external view returns (uint256) {
        return incidents.length;
    }
}
