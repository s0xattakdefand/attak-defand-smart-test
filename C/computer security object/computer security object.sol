// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract SecurityObjectGuard {
    address public owner;

    struct ObjectRecord {
        address creator;
        string objectType;
        bytes32 objectHash;
        bool revoked;
        uint256 createdAt;
    }

    mapping(bytes32 => ObjectRecord) public objects;
    mapping(address => mapping(string => bool)) public authorizedCreators;

    event ObjectCreated(bytes32 indexed id, string objectType, address indexed creator);
    event ObjectRevoked(bytes32 indexed id, address indexed revoker);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    modifier onlyAuthorized(string memory objectType) {
        require(authorizedCreators[msg.sender][objectType], "Not authorized for this object type");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function authorize(address creator, string calldata objectType) external onlyOwner {
        authorizedCreators[creator][objectType] = true;
    }

    function createObject(string calldata objectType, bytes calldata data) external onlyAuthorized(objectType) returns (bytes32 objectId) {
        objectId = keccak256(abi.encodePacked(msg.sender, objectType, data, block.timestamp));
        objects[objectId] = ObjectRecord({
            creator: msg.sender,
            objectType: objectType,
            objectHash: keccak256(data),
            revoked: false,
            createdAt: block.timestamp
        });
        emit ObjectCreated(objectId, objectType, msg.sender);
    }

    function revokeObject(bytes32 objectId) external onlyOwner {
        require(!objects[objectId].revoked, "Already revoked");
        objects[objectId].revoked = true;
        emit ObjectRevoked(objectId, msg.sender);
    }

    function isObjectValid(bytes32 objectId, bytes calldata data) external view returns (bool) {
        ObjectRecord memory obj = objects[objectId];
        return !obj.revoked && obj.objectHash == keccak256(data);
    }
}
