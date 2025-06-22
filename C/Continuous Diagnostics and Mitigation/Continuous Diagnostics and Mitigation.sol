// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CDMMonitor {
    address public admin;
    uint256 public gasLimitThreshold = 500000;
    bool public paused;

    event DiagnosticLogged(address caller, bytes4 selector, uint256 gasUsed, uint256 timestamp);
    event EmergencyTriggered(address indexed by, string reason);

    modifier notPaused() {
        require(!paused, "Paused by CDM");
        _;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function logFunction(bytes4 selector, uint256 gasUsed) external {
        emit DiagnosticLogged(msg.sender, selector, gasUsed, block.timestamp);
        if (gasUsed > gasLimitThreshold) {
            paused = true;
            emit EmergencyTriggered(msg.sender, "Gas usage exceeded threshold");
        }
    }

    function unpause() external onlyAdmin {
        paused = false;
    }

    function isPaused() external view returns (bool) {
        return paused;
    }
}
