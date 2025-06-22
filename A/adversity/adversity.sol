// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AdversityManager — Tracks and mitigates contract adversity conditions
contract AdversityManager {
    address public admin;
    bool public systemPaused;
    uint256 public adversityLevel;

    event AdversityDetected(string reason, uint256 severity);
    event SystemPaused(uint256 level);
    event SystemRecovered();

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier notPaused() {
        require(!systemPaused, "System is under adversity pause");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function reportAdversity(string calldata reason, uint256 severity) external onlyAdmin {
        adversityLevel += severity;
        emit AdversityDetected(reason, severity);

        if (adversityLevel > 100) {
            systemPaused = true;
            emit SystemPaused(adversityLevel);
        }
    }

    function clearAdversity() external onlyAdmin {
        adversityLevel = 0;
        systemPaused = false;
        emit SystemRecovered();
    }

    function getStatus() external view returns (uint256 level, bool paused) {
        return (adversityLevel, systemPaused);
    }
}
