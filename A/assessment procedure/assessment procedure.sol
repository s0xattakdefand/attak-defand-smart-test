// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AssessmentProcedureManager - Step-based evaluation workflow registry for Web3 protocols

contract AssessmentProcedureManager {
    address public admin;

    struct Step {
        string name;
        string description;
        bool completed;
        address executedBy;
        uint256 completedAt;
    }

    struct Procedure {
        string procedureName;
        address target;
        Step[] steps;
        bool finalized;
    }

    mapping(bytes32 => Procedure) public procedures;
    bytes32[] public procedureIds;

    event ProcedureCreated(bytes32 indexed id, address target, string name);
    event StepCompleted(bytes32 indexed procedureId, uint256 stepIndex, address executor);
    event ProcedureFinalized(bytes32 indexed procedureId);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function createProcedure(
        address target,
        string calldata name,
        string[] calldata stepNames,
        string[] calldata stepDescriptions
    ) external onlyAdmin returns (bytes32 id) {
        require(stepNames.length == stepDescriptions.length, "Mismatch");

        id = keccak256(abi.encodePacked(target, name, block.timestamp));
        Procedure storage p = procedures[id];
        p.procedureName = name;
        p.target = target;

        for (uint i = 0; i < stepNames.length; i++) {
            p.steps.push(Step({
                name: stepNames[i],
                description: stepDescriptions[i],
                completed: false,
                executedBy: address(0),
                completedAt: 0
            }));
        }

        procedureIds.push(id);
        emit ProcedureCreated(id, target, name);
        return id;
    }

    function completeStep(bytes32 procedureId, uint256 stepIndex) external onlyAdmin {
        Procedure storage p = procedures[procedureId];
        require(!p.finalized, "Procedure already finalized");
        require(stepIndex < p.steps.length, "Invalid step");

        Step storage s = p.steps[stepIndex];
        require(!s.completed, "Already completed");

        s.completed = true;
        s.executedBy = msg.sender;
        s.completedAt = block.timestamp;

        emit StepCompleted(procedureId, stepIndex, msg.sender);
    }

    function finalizeProcedure(bytes32 procedureId) external onlyAdmin {
        Procedure storage p = procedures[procedureId];
        require(!p.finalized, "Already finalized");
        for (uint i = 0; i < p.steps.length; i++) {
            require(p.steps[i].completed, "Not all steps completed");
        }
        p.finalized = true;
        emit ProcedureFinalized(procedureId);
    }

    function getProcedure(bytes32 id) external view returns (Procedure memory) {
        return procedures[id];
    }

    function getStep(bytes32 id, uint index) external view returns (Step memory) {
        return procedures[id].steps[index];
    }

    function getAllProcedures() external view returns (bytes32[] memory) {
        return procedureIds;
    }
}
