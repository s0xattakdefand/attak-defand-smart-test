// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ObjectAttackDefense - Full Attack and Defense Simulation for Object Misuse in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Vulnerable Object Storage Contract (Insecure Structs and Mutable Access)
contract InsecureObjectStorage {
    struct Asset {
        address owner;
        string data;
    }

    mapping(uint256 => Asset) public assets;
    uint256 public nextId;

    event AssetCreated(uint256 id, address indexed owner, string data);
    event AssetModified(uint256 id, address indexed owner, string data);

    function createAsset(string calldata data) external {
        assets[nextId] = Asset(msg.sender, data);
        emit AssetCreated(nextId, msg.sender, data);
        nextId++;
    }

    function modifyAsset(uint256 id, string calldata newData) external {
        // 🔥 No ownership check!
        assets[id].data = newData;
        emit AssetModified(id, assets[id].owner, newData);
    }
}

/// @notice Secure Object Storage Contract (Strict Ownership, Immutable IDs)
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureObjectStorage is Ownable {
    struct Asset {
        address owner;
        string data;
    }

    mapping(uint256 => Asset) private assets;
    uint256 private nextId;

    event AssetCreated(uint256 id, address indexed owner, string data);
    event AssetModified(uint256 id, address indexed owner, string data);

    function createAsset(string calldata data) external {
        assets[nextId] = Asset(msg.sender, data);
        emit AssetCreated(nextId, msg.sender, data);
        nextId++;
    }

    function modifyAsset(uint256 id, string calldata newData) external {
        require(assets[id].owner == msg.sender, "Not the owner");
        assets[id].data = newData;
        emit AssetModified(id, msg.sender, newData);
    }

    function getAsset(uint256 id) external view returns (address owner, string memory data) {
        Asset memory asset = assets[id];
        return (asset.owner, asset.data);
    }

    function totalAssets() external view returns (uint256) {
        return nextId;
    }
}

/// @notice Attack contract simulating asset hijacking
contract ObjectIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function hijackAsset(uint256 id, string calldata newFakeData) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("modifyAsset(uint256,string)", id, newFakeData)
        );
    }
}
