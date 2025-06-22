// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AssessmentCriterionRegistry - Define and enforce criteria for secure, auditable Web3 evaluation

contract AssessmentCriterionRegistry {
    address public admin;

    struct Criterion {
        string name;
        string description;
        bool required;
        string category; // e.g., "Security", "Governance"
        bool active;
        uint256 createdAt;
    }

    mapping(bytes32 => Criterion) public criteria;
    bytes32[] public criterionIds;

    event CriterionAdded(bytes32 indexed id, string name, bool required, string category);
    event CriterionStatusChanged(bytes32 indexed id, bool active);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function addCriterion(
        string calldata name,
        string calldata description,
        bool required,
        string calldata category
    ) external onlyAdmin returns (bytes32 id) {
        id = keccak256(abi.encodePacked(name, block.timestamp));
        criteria[id] = Criterion({
            name: name,
            description: description,
            required: required,
            category: category,
            active: true,
            createdAt: block.timestamp
        });
        criterionIds.push(id);
        emit CriterionAdded(id, name, required, category);
        return id;
    }

    function setCriterionActive(bytes32 id, bool active) external onlyAdmin {
        require(criteria[id].createdAt != 0, "Criterion not found");
        criteria[id].active = active;
        emit CriterionStatusChanged(id, active);
    }

    function getAllCriteria() external view returns (bytes32[] memory) {
        return criterionIds;
    }

    function getCriterion(bytes32 id) external view returns (Criterion memory) {
        return criteria[id];
    }
}
