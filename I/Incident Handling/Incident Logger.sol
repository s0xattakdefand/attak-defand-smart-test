// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract IncidentHandler {
    enum Severity { Info, Warning, Critical }

    event IncidentReported(
        address indexed reporter,
        Severity level,
        string description,
        uint256 timestamp
    );

    function reportIncident(Severity level, string calldata description) external {
        emit IncidentReported(msg.sender, level, description, block.timestamp);
    }
}
