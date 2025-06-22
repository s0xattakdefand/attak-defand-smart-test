// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ObjectManagementGroupAttackDefense - Attack and Defense Simulation for Object Management Group in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Object Group Management (Anyone Can Modify/Delete Any Object)
contract InsecureObjectGroup {
    struct ManagedObject {
        address creator;
        string data;
        bool exists;
    }

    mapping(uint256 => ManagedObject) public objects;
    uint256 public nextId;

    event ObjectCreated(uint256 indexed id, address indexed creator, string data);
    event ObjectModified(uint256 indexed id, string newData);
    event ObjectDeleted(uint256 indexed id);

    function createObject(string calldata data) external {
        objects[nextId] = ManagedObject(msg.sender, data, true);
        emit ObjectCreated(nextId, msg.sender, data);
        nextId++;
    }

    function modifyObject(uint256 id, string calldata newData) external {
        require(objects[id].exists, "Does not exist");
        objects[id].data = newData;
        emit ObjectModified(id, newData);
    }

    function deleteObject(uint256 id) external {
        require(objects[id].exists, "Does not exist");
        delete objects[id];
        emit ObjectDeleted(id);
    }
}

/// @notice Secure Object Group Management (Strict Role, Creator-Bound Actions)
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureObjectGroup is Ownable {
    struct ManagedObject {
        address creator;
        string data;
        bool exists;
    }

    mapping(uint256 => ManagedObject) private objects;
    uint256 private nextId;

    event ObjectCreated(uint256 indexed id, address indexed creator, string data);
    event ObjectModified(uint256 indexed id, string newData);
    event ObjectDeleted(uint256 indexed id);

    function createObject(string calldata data) external {
        objects[nextId] = ManagedObject(msg.sender, data, true);
        emit ObjectCreated(nextId, msg.sender, data);
        nextId++;
    }

    function modifyObject(uint256 id, string calldata newData) external {
        require(objects[id].exists, "Does not exist");
        require(objects[id].creator == msg.sender, "Not your object");
        objects[id].data = newData;
        emit ObjectModified(id, newData);
    }

    function deleteObject(uint256 id) external {
        require(objects[id].exists, "Does not exist");
        require(objects[id].creator == msg.sender || msg.sender == owner(), "Not authorized");
        delete objects[id];
        emit ObjectDeleted(id);
    }

    function getObject(uint256 id) external view returns (address creator, string memory data, bool exists) {
        ManagedObject memory obj = objects[id];
        return (obj.creator, obj.data, obj.exists);
    }

    function totalObjects() external view returns (uint256) {
        return nextId;
    }
}

/// @notice Attack contract simulating object hijacking
contract ObjectGroupIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function hijackObject(uint256 id, string calldata fakeData) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("modifyObject(uint256,string)", id, fakeData)
        );
    }

    function nukeObject(uint256 id) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("deleteObject(uint256)", id)
        );
    }
}
