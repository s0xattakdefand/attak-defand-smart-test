// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Adaptive Security Appliance (ASA) — Web3 Firewall Layer
contract AdaptiveSecurityAppliance {
    address public admin;
    bool public systemActive = true;

    mapping(address => uint256) public anomalyScore;
    mapping(address => bool) public blocked;

    uint256 public threshold = 3;

    event AccessGranted(address indexed actor, string action);
    event ThreatDetected(address indexed actor, string reason);
    event AccessBlocked(address indexed actor);
    event SystemPaused();
    event SystemUnpaused();

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier firewall(string memory action) {
        require(systemActive, "System paused");
        require(!blocked[msg.sender], "Blocked actor");

        if (_isMalicious(msg.sender, action)) {
            anomalyScore[msg.sender]++;
            emit ThreatDetected(msg.sender, action);

            if (anomalyScore[msg.sender] >= threshold) {
                blocked[msg.sender] = true;
                emit AccessBlocked(msg.sender);
            }

            revert("ASA: Access denied");
        }

        emit AccessGranted(msg.sender, action);
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function _isMalicious(address actor, string memory action) internal view returns (bool) {
        // Example filters (extendable): gas check, role spoof, replay, etc.
        if (gasleft() < 30000 || keccak256(abi.encodePacked(action)) == keccak256("attack")) {
            return true;
        }
        return false;
    }

    function pauseSystem() external onlyAdmin {
        systemActive = false;
        emit SystemPaused();
    }

    function unpauseSystem() external onlyAdmin {
        systemActive = true;
        emit SystemUnpaused();
    }

    function clearThreat(address actor) external onlyAdmin {
        anomalyScore[actor] = 0;
        blocked[actor] = false;
    }

    function getActorStatus(address actor) external view returns (uint256 score, bool isBlocked) {
        return (anomalyScore[actor], blocked[actor]);
    }
}
