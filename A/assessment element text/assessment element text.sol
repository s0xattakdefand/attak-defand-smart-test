// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AssessmentElementTextRegistry - On-chain text commentary for evaluation criteria and audit scoring

contract AssessmentElementTextRegistry {
    address public admin;

    struct ElementText {
        bytes32 elementId;      // Could match criterion ID or custom hash
        address evaluator;
        string category;        // e.g., "Security", "Governance"
        string rating;          // e.g., "Pass", "Warning", "Fail"
        string text;            // Human-readable explanation
        uint256 timestamp;
    }

    mapping(bytes32 => ElementText) public elements;
    bytes32[] public elementIds;

    event ElementTextRecorded(bytes32 indexed id, bytes32 elementId, address evaluator, string rating);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function recordElementText(
        bytes32 elementId,
        string calldata category,
        string calldata rating,
        string calldata text
    ) external onlyAdmin returns (bytes32 id) {
        id = keccak256(abi.encodePacked(elementId, msg.sender, block.timestamp));
        elements[id] = ElementText({
            elementId: elementId,
            evaluator: msg.sender,
            category: category,
            rating: rating,
            text: text,
            timestamp: block.timestamp
        });
        elementIds.push(id);
        emit ElementTextRecorded(id, elementId, msg.sender, rating);
        return id;
    }

    function getAllElementTexts() external view returns (bytes32[] memory) {
        return elementIds;
    }

    function getElementText(bytes32 id) external view returns (ElementText memory) {
        return elements[id];
    }
}
