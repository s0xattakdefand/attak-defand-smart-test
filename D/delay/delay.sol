// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// PathDelayTimelock contract for managing delayed execution of actions
contract PathDelayTimelock {
    // Owner of the contract
    address public owner;

    // Structure to represent a delayed action
    struct DelayedAction {
        address executor; // Address authorized to execute the action
        bytes data; // Encoded function call data
        uint256 delay; // Delay in seconds
        uint256 scheduledAt; // Timestamp when action was scheduled
        bool executed; // Whether the action has been executed
        bool exists; // Whether the action exists
    }

    // Mapping to store delayed actions by action ID
    mapping(bytes32 => DelayedAction) public delayedActions;

    // Minimum and maximum delay periods (in seconds)
    uint256 public constant MIN_DELAY = 1 hours;
    uint256 public constant MAX_DELAY = 30 days;

    // Event emitted when an action is scheduled
    event ActionScheduled(bytes32 indexed actionId, address executor, bytes data, uint256 delay, uint256 scheduledAt);

    // Event emitted when an action is executed
    event ActionExecuted(bytes32 indexed actionId, address executor, uint256 executedAt);

    // Event emitted when an action is canceled
    event ActionCanceled(bytes32 indexed actionId, address canceler);

    // Modifier to restrict functions to the contract owner
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    // Modifier to check if action exists
    modifier actionExists(bytes32 actionId) {
        require(delayedActions[actionId].exists, "Action does not exist");
        _;
    }

    // Constructor to set the owner
    constructor() {
        owner = msg.sender;
    }

    // Function to schedule a delayed action
    function scheduleAction(
        bytes32 actionId,
        address executor,
        bytes calldata data,
        uint256 delay
    ) external onlyOwner {
        require(!delayedActions[actionId].exists, "Action ID already exists");
        require(executor != address(0), "Executor cannot be zero address");
        require(delay >= MIN_DELAY && delay <= MAX_DELAY, "Delay out of bounds");
        require(data.length > 0, "Action data cannot be empty");

        delayedActions[actionId] = DelayedAction({
            executor: executor,
            data: data,
            delay: delay,
            scheduledAt: block.timestamp,
            executed: false,
            exists: true
        });

        emit ActionScheduled(actionId, executor, data, delay, block.timestamp);
    }

    // Function to execute a delayed action
    function executeAction(bytes32 actionId) external actionExists(actionId) {
        DelayedAction storage action = delayedActions[actionId];
        require(msg.sender == action.executor, "Only executor can execute");
        require(!action.executed, "Action already executed");
        require(block.timestamp >= action.scheduledAt + action.delay, "Delay period not elapsed");

        action.executed = true;

        // Execute the action by calling the encoded function
        (bool success, ) = address(this).call(action.data);
        require(success, "Action execution failed");

        emit ActionExecuted(actionId, msg.sender, block.timestamp);
    }

    // Function to cancel a scheduled action
    function cancelAction(bytes32 actionId) external onlyOwner actionExists(actionId) {
        DelayedAction storage action = delayedActions[actionId];
        require(!action.executed, "Cannot cancel executed action");

        action.exists = false;
        emit ActionCanceled(actionId, msg.sender);
    }

    // Function to check if an action can be executed
    function canExecute(bytes32 actionId) external view actionExists(actionId) returns (bool) {
        DelayedAction memory action = delayedActions[actionId];
        return !action.executed && block.timestamp >= action.scheduledAt + action.delay;
    }

    // Function to get action details
    function getActionDetails(bytes32 actionId)
        external
        view
        actionExists(actionId)
        returns (address executor, bytes memory data, uint256 delay, uint256 scheduledAt, bool executed)
    {
        DelayedAction memory action = delayedActions[actionId];
        return (action.executor, action.data, action.delay, action.scheduledAt, action.executed);
    }

    // Function to transfer ownership
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "New owner cannot be zero address");
        owner = newOwner;
    }

    // Fallback function to receive encoded action calls
    receive() external payable {}
}