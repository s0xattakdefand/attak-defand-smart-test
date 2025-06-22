// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AssessmentObjectRegistry - Tracks what smart contract objects are evaluated in Web3 assessments

contract AssessmentObjectRegistry {
    address public admin;

    enum ObjectType { Contract, DAOProcess, Oracle, ZKVerifier, Proxy, Bridge }

    struct ObjectInfo {
        bytes32 objectId;
        address targetAddress;
        ObjectType objType;
        string name;
        string version;           // Optional semantic version or commit hash
        string description;
        uint256 registeredAt;
    }

    mapping(bytes32 => ObjectInfo) public objects;
    bytes32[] public objectIds;

    event ObjectRegistered(bytes32 indexed id, address target, ObjectType objType, string name);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerObject(
        address target,
        ObjectType objType,
        string calldata name,
        string calldata version,
        string calldata description
    ) external onlyAdmin returns (bytes32 id) {
        id = keccak256(abi.encodePacked(target, name, block.timestamp));
        objects[id] = ObjectInfo({
            objectId: id,
            targetAddress: target,
            objType: objType,
            name: name,
            version: version,
            description: description,
            registeredAt: block.timestamp
        });
        objectIds.push(id);
        emit ObjectRegistered(id, target, objType, name);
        return id;
    }

    function getObject(bytes32 id) external view returns (ObjectInfo memory) {
        return objects[id];
    }

    function getAllObjects() external view returns (bytes32[] memory) {
        return objectIds;
    }
}
