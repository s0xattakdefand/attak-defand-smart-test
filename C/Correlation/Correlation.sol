// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CorrelationTracker {
    address public admin;
    bool public correlationEnabled;

    struct Action {
        bytes32 anonId;        // hashed session/user identifier
        string actionType;
        uint256 timestamp;
    }

    Action[] public logs;

    event ActionLogged(bytes32 indexed anonId, string actionType, uint256 timestamp);
    event CorrelationModeUpdated(bool enabled);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
        correlationEnabled = true;
    }

    function toggleCorrelation(bool enabled) external onlyAdmin {
        correlationEnabled = enabled;
        emit CorrelationModeUpdated(enabled);
    }

    // Anonymous user logs an action
    function logAction(bytes32 anonId, string calldata actionType) external {
        require(correlationEnabled, "Correlation is disabled");

        Action memory newLog = Action({
            anonId: anonId,
            actionType: actionType,
            timestamp: block.timestamp
        });

        logs.push(newLog);
        emit ActionLogged(anonId, actionType, block.timestamp);
    }

    // Public view of action count
    function getTotalActions() external view returns (uint256) {
        return logs.length;
    }

    // Get logs by index
    function getLog(uint256 index) external view returns (bytes32, string memory, uint256) {
        Action memory a = logs[index];
        return (a.anonId, a.actionType, a.timestamp);
    }
}
