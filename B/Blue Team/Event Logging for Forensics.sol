// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ForensicEventLogger {
    address public admin;

    event SuspiciousActivity(address indexed source, string message);

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin allowed");
        _;
    }

    /**
     * @notice Trigger an alert for forensic logging (e.g., via Chainlink or Forta).
     * @param reason Description of suspicious behavior or anomaly.
     */
    function reportSuspiciousActivity(string calldata reason) public onlyAdmin {
        emit SuspiciousActivity(msg.sender, reason);
    }

    /**
     * @notice Simulated public activity for example use.
     */
    function simulateAnomaly() public {
        // This is where an automated hook could be added
        emit SuspiciousActivity(msg.sender, "Simulated anomaly triggered");
    }
}
