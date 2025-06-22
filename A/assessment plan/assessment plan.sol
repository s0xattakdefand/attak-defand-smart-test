// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AssessmentPlanRegistry - Defines and tracks structured evaluation plans for Web3 protocol components

contract AssessmentPlanRegistry {
    address public admin;

    struct Plan {
        bytes32 id;
        address target;
        string planName;
        string scope;           // e.g., "Vault.sol + Proxy"
        string criteriaList;    // e.g., "Reentrancy, RoleCheck, UpgradeSafety"
        string approach;        // e.g., "Audit", "ZKSim", "FormalProof"
        string boundaryNotes;   // Optional exclusions or trust assumptions
        string status;          // e.g., "Pending", "Approved", "Failed"
        uint256 createdAt;
    }

    mapping(bytes32 => Plan) public plans;
    bytes32[] public planIds;

    event PlanCreated(bytes32 indexed id, address target, string planName);
    event PlanStatusUpdated(bytes32 indexed id, string status);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function createPlan(
        address target,
        string calldata planName,
        string calldata scope,
        string calldata criteriaList,
        string calldata approach,
        string calldata boundaryNotes
    ) external onlyAdmin returns (bytes32 id) {
        id = keccak256(abi.encodePacked(target, planName, block.timestamp));
        plans[id] = Plan({
            id: id,
            target: target,
            planName: planName,
            scope: scope,
            criteriaList: criteriaList,
            approach: approach,
            boundaryNotes: boundaryNotes,
            status: "Pending",
            createdAt: block.timestamp
        });
        planIds.push(id);
        emit PlanCreated(id, target, planName);
        return id;
    }

    function updatePlanStatus(bytes32 id, string calldata newStatus) external onlyAdmin {
        require(plans[id].createdAt != 0, "Plan not found");
        plans[id].status = newStatus;
        emit PlanStatusUpdated(id, newStatus);
    }

    function getAllPlans() external view returns (bytes32[] memory) {
        return planIds;
    }

    function getPlan(bytes32 id) external view returns (Plan memory) {
        return plans[id];
    }
}
