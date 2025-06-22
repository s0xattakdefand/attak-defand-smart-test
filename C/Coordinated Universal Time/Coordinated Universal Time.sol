// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract UTCSecureTime {
    address public owner;

    struct Action {
        bool executed;
        uint256 timestamp;
    }

    mapping(bytes32 => Action) public actions;

    uint256 public allowedTimeWindow = 300; // Allowed time window (5 minutes)

    event ActionExecuted(bytes32 indexed actionId, uint256 timestamp);
    event AllowedTimeWindowUpdated(uint256 newTimeWindow);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // Owner can update allowed time window
    function updateAllowedTimeWindow(uint256 _newTimeWindow) external onlyOwner {
        allowedTimeWindow = _newTimeWindow;
        emit AllowedTimeWindowUpdated(_newTimeWindow);
    }

    // Secure execution with UTC-based timestamp validation
    function executeTimedAction(bytes32 actionId, uint256 actionTimestamp) external {
        require(!actions[actionId].executed, "Action already executed");
        
        // Block timestamp should be close to actionTimestamp within allowed window
        require(
            block.timestamp >= actionTimestamp && 
            block.timestamp <= actionTimestamp + allowedTimeWindow,
            "Timestamp outside allowed window"
        );

        actions[actionId] = Action(true, block.timestamp);
        emit ActionExecuted(actionId, block.timestamp);
    }

    // Check action status
    function checkActionStatus(bytes32 actionId) external view returns (bool, uint256) {
        Action memory action = actions[actionId];
        return (action.executed, action.timestamp);
    }
}
