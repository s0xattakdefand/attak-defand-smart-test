// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ConflictResolutionCenter {
    enum Status { Pending, Resolved, Rejected }

    struct Action {
        string target;
        bytes32 actionHash;
        address proposer;
        uint256 timestamp;
        Status status;
    }

    uint256 public actionCount;
    mapping(uint256 => Action) public actions;
    mapping(string => uint256) public latestByTarget;

    event ActionProposed(uint256 indexed id, string target, bytes32 actionHash);
    event ConflictDetected(uint256 newId, uint256 existingId, string target);
    event ActionResolved(uint256 indexed id);

    function proposeAction(string calldata target, bytes32 actionHash) external returns (uint256 id) {
        id = actionCount++;
        actions[id] = Action(target, actionHash, msg.sender, block.timestamp, Status.Pending);

        uint256 existingId = latestByTarget[target];
        if (actions[existingId].status == Status.Pending) {
            emit ConflictDetected(id, existingId, target);
        }

        latestByTarget[target] = id;
        emit ActionProposed(id, target, actionHash);
    }

    function resolveAction(uint256 id) external {
        require(actions[id].status == Status.Pending, "Already resolved");
        actions[id].status = Status.Resolved;
        emit ActionResolved(id);
    }

    function getLatestForTarget(string calldata target) external view returns (Action memory) {
        return actions[latestByTarget[target]];
    }
}
