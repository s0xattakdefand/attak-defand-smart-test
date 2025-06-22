// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AssessmentElementRegistry - Define and manage modular assessment elements for Web3 evaluations

contract AssessmentElementRegistry {
    address public admin;

    enum ElementType { Criterion, Objective, ProcedureStep, Object, Finding, Result }

    struct Element {
        bytes32 id;
        ElementType elemType;
        string name;              // e.g., "No Selfdestruct", "Run Fuzz Test"
        string category;          // e.g., "Security", "Governance", "Performance"
        string description;
        uint256 createdAt;
    }

    mapping(bytes32 => Element) public elements;
    bytes32[] public elementIds;

    event ElementDefined(bytes32 indexed id, ElementType elemType, string name, string category);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function defineElement(
        ElementType elemType,
        string calldata name,
        string calldata category,
        string calldata description
    ) external onlyAdmin returns (bytes32 id) {
        id = keccak256(abi.encodePacked(name, elemType, block.timestamp));
        elements[id] = Element({
            id: id,
            elemType: elemType,
            name: name,
            category: category,
            description: description,
            createdAt: block.timestamp
        });
        elementIds.push(id);
        emit ElementDefined(id, elemType, name, category);
        return id;
    }

    function getElement(bytes32 id) external view returns (Element memory) {
        return elements[id];
    }

    function getAllElementIds() external view returns (bytes32[] memory) {
        return elementIds;
    }
}
