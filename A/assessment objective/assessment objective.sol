// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AssessmentObjectiveRegistry - Track goals and intent behind assessments in Web3

contract AssessmentObjectiveRegistry {
    address public admin;

    struct Objective {
        bytes32 objectiveId;
        string name;            // e.g., "No Reentrancy", "Gas Under 300K"
        string description;
        string category;        // e.g., "Security", "Performance"
        address linkedTarget;   // Optional: contract or module assessed
        bytes32 linkedPlanId;   // Optional: if tied to assessment plan
        uint256 createdAt;
    }

    mapping(bytes32 => Objective) public objectives;
    bytes32[] public objectiveIds;

    event ObjectiveRegistered(bytes32 indexed id, string name, string category);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerObjective(
        string calldata name,
        string calldata description,
        string calldata category,
        address linkedTarget,
        bytes32 linkedPlanId
    ) external onlyAdmin returns (bytes32 id) {
        id = keccak256(abi.encodePacked(name, block.timestamp));
        objectives[id] = Objective({
            objectiveId: id,
            name: name,
            description: description,
            category: category,
            linkedTarget: linkedTarget,
            linkedPlanId: linkedPlanId,
            createdAt: block.timestamp
        });
        objectiveIds.push(id);
        emit ObjectiveRegistered(id, name, category);
        return id;
    }

    function getObjective(bytes32 id) external view returns (Objective memory) {
        return objectives[id];
    }

    function getAllObjectives() external view returns (bytes32[] memory) {
        return objectiveIds;
    }
}
