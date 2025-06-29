// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/Ownable.sol";

/// @title IDataStorage  
/// @notice Interface for low-level on-chain data storage.
interface IDataStorage {
    function create(bytes calldata value) external returns (uint256 id);
    function read(uint256 id) external view returns (bytes memory);
    function update(uint256 id, bytes calldata value) external;
    function remove(uint256 id) external;
}

/// @title DataStorage  
/// @notice A minimal on-chain key–value store.  
/// Records are identified by incremental uint256 IDs.  
contract DataStorage is IDataStorage, Ownable {
    mapping(uint256 => bytes) private _data;
    uint256 private _nextId = 1;

    /// @notice Set the deployer as the initial owner
    constructor() Ownable(msg.sender) {}

    /// @inheritdoc IDataStorage
    function create(bytes calldata value) external override onlyOwner returns (uint256 id) {
        id = _nextId++;
        _data[id] = value;
    }

    /// @inheritdoc IDataStorage
    function read(uint256 id) external view override returns (bytes memory) {
        bytes memory v = _data[id];
        require(v.length != 0, "DataStorage: nonexistent id");
        return v;
    }

    /// @inheritdoc IDataStorage
    function update(uint256 id, bytes calldata value) external override onlyOwner {
        require(_data[id].length != 0, "DataStorage: nonexistent id");
        _data[id] = value;
    }

    /// @inheritdoc IDataStorage
    function remove(uint256 id) external override onlyOwner {
        require(_data[id].length != 0, "DataStorage: nonexistent id");
        delete _data[id];
    }
}
