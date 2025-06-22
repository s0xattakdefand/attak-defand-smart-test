// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AttackSensingAndWarning - Real-time threat sensing and alert system

contract AttackSensingAndWarning {
    address public admin;
    uint256 public warningThreshold = 3;

    struct Warning {
        address actor;
        string reason;
        uint256 timestamp;
        uint256 severity; // 1 = info, 2 = warn, 3 = critical
    }

    Warning[] public warnings;
    mapping(address => uint256) public callCount;
    mapping(address => uint256) public lastBlockSeen;

    event WarningLogged(address indexed actor, string reason, uint256 severity);
    event AutoPaused(string reason);

    bool public paused;

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier notPaused() {
        require(!paused, "System is paused");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    // Core sensing logic
    function senseAccessPattern(address actor) external notPaused {
        if (lastBlockSeen[actor] == block.number) {
            callCount[actor]++;
        } else {
            callCount[actor] = 1;
            lastBlockSeen[actor] = block.number;
        }

        if (callCount[actor] > warningThreshold) {
            _logWarning(actor, "Rapid repeated access", 3);
            paused = true;
            emit AutoPaused("Excessive access rate");
        }
    }

    function senseRoleChange(address actor, string calldata role) external onlyAdmin {
        _logWarning(actor, string.concat("Role escalation to ", role), 2);
    }

    function senseUpgrade(address newImpl) external onlyAdmin {
        _logWarning(newImpl, "Unverified logic upgrade detected", 3);
    }

    function _logWarning(address actor, string memory reason, uint256 severity) internal {
        warnings.push(Warning({
            actor: actor,
            reason: reason,
            timestamp: block.timestamp,
            severity: severity
        }));
        emit WarningLogged(actor, reason, severity);
    }

    function getWarnings() external view returns (Warning[] memory) {
        return warnings;
    }

    function setPaused(bool status) external onlyAdmin {
        paused = status;
    }

    function setWarningThreshold(uint256 threshold) external onlyAdmin {
        warningThreshold = threshold;
    }
}
