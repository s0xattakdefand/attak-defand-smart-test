// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AssessmentElementAttributeRegistry - Metadata and tagging for assessment elements in Web3

contract AssessmentElementAttributeRegistry {
    address public admin;

    enum ValueType { Bool, Uint, String }

    struct Attribute {
        bytes32 id;
        bytes32 elementId;
        string key;             // e.g., "severity", "required"
        ValueType valueType;
        string stringValue;
        uint256 uintValue;
        bool boolValue;
        uint256 createdAt;
    }

    mapping(bytes32 => Attribute) public attributes;
    mapping(bytes32 => bytes32[]) public elementToAttributes;

    event AttributeSet(bytes32 indexed id, bytes32 indexed elementId, string key);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function setStringAttribute(
        bytes32 elementId,
        string calldata key,
        string calldata value
    ) external onlyAdmin returns (bytes32 id) {
        id = keccak256(abi.encodePacked(elementId, key, value, block.timestamp));
        attributes[id] = Attribute({
            id: id,
            elementId: elementId,
            key: key,
            valueType: ValueType.String,
            stringValue: value,
            uintValue: 0,
            boolValue: false,
            createdAt: block.timestamp
        });
        elementToAttributes[elementId].push(id);
        emit AttributeSet(id, elementId, key);
        return id;
    }

    function setBoolAttribute(
        bytes32 elementId,
        string calldata key,
        bool value
    ) external onlyAdmin returns (bytes32 id) {
        id = keccak256(abi.encodePacked(elementId, key, value, block.timestamp));
        attributes[id] = Attribute({
            id: id,
            elementId: elementId,
            key: key,
            valueType: ValueType.Bool,
            stringValue: "",
            uintValue: 0,
            boolValue: value,
            createdAt: block.timestamp
        });
        elementToAttributes[elementId].push(id);
        emit AttributeSet(id, elementId, key);
        return id;
    }

    function setUintAttribute(
        bytes32 elementId,
        string calldata key,
        uint256 value
    ) external onlyAdmin returns (bytes32 id) {
        id = keccak256(abi.encodePacked(elementId, key, value, block.timestamp));
        attributes[id] = Attribute({
            id: id,
            elementId: elementId,
            key: key,
            valueType: ValueType.Uint,
            stringValue: "",
            uintValue: value,
            boolValue: false,
            createdAt: block.timestamp
        });
        elementToAttributes[elementId].push(id);
        emit AttributeSet(id, elementId, key);
        return id;
    }

    function getAttributes(bytes32 elementId) external view returns (bytes32[] memory) {
        return elementToAttributes[elementId];
    }

    function getAttribute(bytes32 id) external view returns (Attribute memory) {
        return attributes[id];
    }
}
