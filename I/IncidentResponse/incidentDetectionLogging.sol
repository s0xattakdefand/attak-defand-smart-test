// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract IncidentReporter {
    enum Severity { Info, Warning, Critical }

    event IncidentDetected(address indexed reporter, Severity level, string description);

    function report(string calldata desc, Severity level) external {
        emit IncidentDetected(msg.sender, level, desc);
    }
}
