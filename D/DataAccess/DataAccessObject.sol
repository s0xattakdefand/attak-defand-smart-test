// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/Ownable.sol";
import "./DataStorage.sol";  // or the path to your DataStorage.sol

/// @title DataAccessObject  
/// @notice “DAO” facade that enforces business rules on top of IDataStorage.
/// Only the DAO’s owner may perform writes; anyone may read.
contract DataAccessObject is Ownable {
    IDataStorage public storageContract;

    event RecordCreated(uint256 indexed id, address indexed creator);
    event RecordUpdated(uint256 indexed id, address indexed updater);
    event RecordDeleted(uint256 indexed id, address indexed deleter);

    /// @notice Deploy-time: set storage address and DAO owner
    /// @param storageAddr Address of an IDataStorage contract
    constructor(address storageAddr) Ownable(msg.sender) {
        require(storageAddr != address(0), "DAO: zero storage address");
        storageContract = IDataStorage(storageAddr);
    }

    /// @notice Point to a new storage contract (upgrade).
    function setStorageContract(address newStorage) external onlyOwner {
        require(newStorage != address(0), "DAO: zero address");
        storageContract = IDataStorage(newStorage);
    }

    /// @notice Create a new record. Emits RecordCreated.
    function createRecord(bytes calldata value) external onlyOwner returns (uint256 id) {
        id = storageContract.create(value);
        emit RecordCreated(id, msg.sender);
    }

    /// @notice Read a record by ID. Publicly accessible.
    function getRecord(uint256 id) external view returns (bytes memory) {
        return storageContract.read(id);
    }

    /// @notice Update an existing record. Emits RecordUpdated.
    function updateRecord(uint256 id, bytes calldata value) external onlyOwner {
        storageContract.update(id, value);
        emit RecordUpdated(id, msg.sender);
    }

    /// @notice Delete a record. Emits RecordDeleted.
    function deleteRecord(uint256 id) external onlyOwner {
        storageContract.remove(id);
        emit RecordDeleted(id, msg.sender);
    }
}
