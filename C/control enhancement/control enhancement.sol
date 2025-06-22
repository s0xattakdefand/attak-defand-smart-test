// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract EnhancedControlManager {
    address public owner;
    address public pendingOwner;
    uint256 public transferRequestTime;
    uint256 public constant TIMELOCK_DELAY = 1 days;

    mapping(address => bool) public operators;
    mapping(bytes32 => bool) public executedActions;

    event OwnershipTransferRequested(address indexed newOwner, uint256 timestamp);
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);
    event OperatorSet(address indexed operator, bool enabled);
    event ActionExecuted(address indexed caller, string actionKey);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyOperator() {
        require(operators[msg.sender], "Not operator");
        _;
    }

    modifier withTimelock(string memory actionKey) {
        bytes32 hash = keccak256(abi.encodePacked(actionKey));
        require(!executedActions[hash], "Already executed");
        executedActions[hash] = true;
        _;
        emit ActionExecuted(msg.sender, actionKey);
    }

    constructor() {
        owner = msg.sender;
    }

    // 🔐 Enhanced Role Control
    function setOperator(address user, bool enabled) external onlyOwner {
        operators[user] = enabled;
        emit OperatorSet(user, enabled);
    }

    // 🕒 Ownership Transfer with Timelock
    function requestOwnershipTransfer(address newOwner) external onlyOwner {
        pendingOwner = newOwner;
        transferRequestTime = block.timestamp;
        emit OwnershipTransferRequested(newOwner, transferRequestTime);
    }

    function finalizeOwnershipTransfer() external {
        require(msg.sender == pendingOwner, "Not pending owner");
        require(block.timestamp >= transferRequestTime + TIMELOCK_DELAY, "Timelock not met");
        emit OwnershipTransferred(owner, pendingOwner);
        owner = pendingOwner;
        pendingOwner = address(0);
    }

    // 🧠 Enhanced Critical Action (e.g., contract upgrade or oracle reset)
    function criticalAction(string calldata key)
        external
        onlyOperator
        withTimelock(key)
        returns (string memory)
    {
        return "Critical action executed with enhanced control.";
    }
}
