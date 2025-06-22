// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AssessmentCompletenessTracker - Validate full coverage and readiness of a Web3 protocol assessment

contract AssessmentCompletenessTracker {
    address public admin;

    struct ElementStatus {
        bytes32 elementId;
        string elementType;   // e.g., "Criterion", "Finding"
        bool required;
        bool completed;
        uint256 updatedAt;
    }

    mapping(bytes32 => ElementStatus) public elements;
    bytes32[] public elementIds;

    event ElementAdded(bytes32 indexed id, string elementType, bool required);
    event ElementCompleted(bytes32 indexed id);
    event ElementReset(bytes32 indexed id);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function addElement(
        bytes32 elementId,
        string calldata elementType,
        bool required
    ) external onlyAdmin {
        require(elements[elementId].updatedAt == 0, "Already tracked");
        elements[elementId] = ElementStatus({
            elementId: elementId,
            elementType: elementType,
            required: required,
            completed: false,
            updatedAt: block.timestamp
        });
        elementIds.push(elementId);
        emit ElementAdded(elementId, elementType, required);
    }

    function markCompleted(bytes32 elementId) external onlyAdmin {
        require(elements[elementId].updatedAt != 0, "Not tracked");
        elements[elementId].completed = true;
        elements[elementId].updatedAt = block.timestamp;
        emit ElementCompleted(elementId);
    }

    function resetElement(bytes32 elementId) external onlyAdmin {
        require(elements[elementId].updatedAt != 0, "Not tracked");
        elements[elementId].completed = false;
        elements[elementId].updatedAt = block.timestamp;
        emit ElementReset(elementId);
    }

    function isComplete() external view returns (bool complete) {
        for (uint i = 0; i < elementIds.length; i++) {
            ElementStatus memory e = elements[elementIds[i]];
            if (e.required && !e.completed) {
                return false;
            }
        }
        return true;
    }

    function getAllElementIds() external view returns (bytes32[] memory) {
        return elementIds;
    }

    function getElement(bytes32 id) external view returns (ElementStatus memory) {
        return elements[id];
    }
}
