// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CNCExecutor {
    address public admin;

    struct Task {
        bytes data;
        bytes32 hash;
        bool executed;
        uint256 timestamp;
    }

    mapping(uint256 => Task) public tasks;

    event TaskRegistered(uint256 indexed id, bytes32 hash);
    event TaskExecuted(uint256 indexed id, address indexed executor);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerTask(uint256 id, bytes calldata data) external onlyAdmin {
        require(tasks[id].timestamp == 0, "Task exists");
        bytes32 hash = keccak256(data);
        tasks[id] = Task({
            data: data,
            hash: hash,
            executed: false,
            timestamp: block.timestamp
        });
        emit TaskRegistered(id, hash);
    }

    function executeTask(uint256 id) external {
        Task storage task = tasks[id];
        require(task.timestamp != 0, "Task not found");
        require(!task.executed, "Already executed");

        bytes32 computedHash = keccak256(task.data);
        require(computedHash == task.hash, "Hash mismatch");

        (bool success, ) = address(this).call(task.data);
        require(success, "Execution failed");

        task.executed = true;
        emit TaskExecuted(id, msg.sender);
    }

    function verifyTask(uint256 id) external view returns (bool) {
        Task memory task = tasks[id];
        return keccak256(task.data) == task.hash && !task.executed;
    }
}
