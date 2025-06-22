// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ConceptOfOperations — End-to-End Ops Management with Roles, Guards, and Logging

contract ConceptOfOperations {
    address public owner;
    bool public paused;

    mapping(address => bool) public operators;
    mapping(bytes32 => bool) public executedOps;
    uint256 public nonce;

    event OperationExecuted(bytes32 indexed opHash, address indexed sender, uint256 value);
    event OperationPaused(address indexed by);
    event OperationUnpaused(address indexed by);
    event OperatorSet(address indexed op, bool enabled);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyOperator() {
        require(operators[msg.sender], "Not operator");
        _;
    }

    modifier notPaused() {
        require(!paused, "Ops paused");
        _;
    }

    constructor() {
        owner = msg.sender;
        operators[owner] = true;
    }

    // === Admin-Controlled Operation ===
    function setOperator(address op, bool enabled) external onlyOwner {
        operators[op] = enabled;
        emit OperatorSet(op, enabled);
    }

    function pauseOperations() external onlyOwner {
        paused = true;
        emit OperationPaused(msg.sender);
    }

    function unpauseOperations() external onlyOwner {
        paused = false;
        emit OperationUnpaused(msg.sender);
    }

    // === User-Initiated Operation ===
    function performUserAction(uint256 value) external notPaused returns (bytes32) {
        bytes32 opHash = keccak256(abi.encodePacked(msg.sender, value, nonce));
        require(!executedOps[opHash], "Replay blocked");

        executedOps[opHash] = true;
        nonce++;

        emit OperationExecuted(opHash, msg.sender, value);
        return opHash;
    }

    // === Reactive Oracle-Based Operation (Simulated) ===
    function executeTriggeredOp(uint256 conditionValue, address target) external onlyOperator notPaused {
        require(conditionValue > 1000, "Condition failed");

        // Example logic: sweep tokens, trigger payout, etc.
        // (Simulated logic here)

        emit OperationExecuted(keccak256(abi.encodePacked("oracle-op", target, conditionValue)), target, conditionValue);
    }
}
