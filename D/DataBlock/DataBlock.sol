// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title BlockRegistry
 * @notice
 *   Implements on‐chain storage and management of fixed‐size “blocks”  
 *   (a sequence of bits whose length equals the block size of the block cipher,  
 *   e.g. 128 bits / 16 bytes for AES).  
 *
 *   Data Model:
 *   • Each block is exactly 16 bytes (`bytes16`).  
 *   • Blocks are assigned incremental IDs.  
 *   • Owners may register and delete their own blocks.  
 *
 * Roles:
 *   • DEFAULT_ADMIN_ROLE: can pause/unpause and revoke any block.  
 *   • Users (no special role) may add or delete (their own) blocks when not paused.
 */
contract BlockRegistry is AccessControl, Pausable {
    bytes32 public constant ADMIN_ROLE = DEFAULT_ADMIN_ROLE;

    struct BlockEntry {
        address owner;
        bytes16 data;   // exactly one cipher‐block (128 bits)
        bool    exists;
    }

    uint256 private _nextId = 1;
    mapping(uint256 => BlockEntry) private _blocks;

    event BlockRegistered(uint256 indexed blockId, address indexed owner, bytes16 data);
    event BlockDeleted   (uint256 indexed blockId, address indexed owner);

    modifier onlyAdmin() {
        require(hasRole(ADMIN_ROLE, msg.sender), "BlockRegistry: not admin");
        _;
    }

    modifier onlyBlockOwner(uint256 blockId) {
        require(_blocks[blockId].exists, "BlockRegistry: block not found");
        require(_blocks[blockId].owner == msg.sender, "BlockRegistry: not owner");
        _;
    }

    constructor(address admin) {
        _grantRole(ADMIN_ROLE, admin);
    }

    /// @notice Pause registry operations.
    function pause() external onlyAdmin {
        _pause();
    }

    /// @notice Unpause registry operations.
    function unpause() external onlyAdmin {
        _unpause();
    }

    /// @notice Register a new 16‐byte block.  
    /// @param data 16 bytes of block data.
    /// @return blockId  Unique ID assigned to this block.
    function registerBlock(bytes16 data)
        external
        whenNotPaused
        returns (uint256 blockId)
    {
        blockId = _nextId++;
        _blocks[blockId] = BlockEntry({
            owner:  msg.sender,
            data:   data,
            exists: true
        });
        emit BlockRegistered(blockId, msg.sender, data);
    }

    /// @notice Delete one of your blocks.
    function deleteBlock(uint256 blockId)
        external
        whenNotPaused
        onlyBlockOwner(blockId)
    {
        delete _blocks[blockId];
        emit BlockDeleted(blockId, msg.sender);
    }

    /// @notice Admin may delete any block.
    function adminDeleteBlock(uint256 blockId)
        external
        whenNotPaused
        onlyAdmin
    {
        require(_blocks[blockId].exists, "BlockRegistry: block not found");
        address owner = _blocks[blockId].owner;
        delete _blocks[blockId];
        emit BlockDeleted(blockId, owner);
    }

    /// @notice Retrieve a block’s data and owner.
    function getBlock(uint256 blockId)
        external
        view
        returns (address owner, bytes16 data)
    {
        BlockEntry storage entry = _blocks[blockId];
        require(entry.exists, "BlockRegistry: block not found");
        return (entry.owner, entry.data);
    }

    /// @notice Total number of blocks ever registered (IDs are sequential).
    function totalBlocks() external view returns (uint256) {
        return _nextId - 1;
    }
}
