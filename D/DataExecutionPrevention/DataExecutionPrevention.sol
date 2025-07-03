// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title DataExecutionPrevention
 * @notice
 *   Implements an on-chain “Data Execution Prevention” pattern:
 *   • Arbitrary data blobs can be stored and retrieved by ID.  
 *   • No code execution paths (delegatecall, fallback, receive) are provided,  
 *     so stored data cannot be executed as code.  
 *   • Access is controlled via roles:
 *       – ADMIN_ROLE may grant/revoke WRITER_ROLE and pause/unpause.  
 *       – WRITER_ROLE may store or delete data.  
 */
contract DataExecutionPrevention is AccessControl, Pausable {
    bytes32 public constant ADMIN_ROLE  = keccak256("ADMIN_ROLE");
    bytes32 public constant WRITER_ROLE = keccak256("WRITER_ROLE");

    // id → arbitrary data blob
    mapping(uint256 => bytes) private _dataStore;

    event DataStored(uint256 indexed id, address indexed writer, uint256 size);
    event DataDeleted(uint256 indexed id, address indexed writer);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);
    }

    modifier onlyAdmin() {
        require(hasRole(ADMIN_ROLE, msg.sender), "DEP: not admin");
        _;
    }

    modifier onlyWriter() {
        require(hasRole(WRITER_ROLE, msg.sender), "DEP: not writer");
        _;
    }

    /// @notice Grant WRITER_ROLE to an account
    function addWriter(address account) external onlyAdmin {
        grantRole(WRITER_ROLE, account);
    }

    /// @notice Revoke WRITER_ROLE from an account
    function removeWriter(address account) external onlyAdmin {
        revokeRole(WRITER_ROLE, account);
    }

    /// @notice Pause storage operations
    function pause() external onlyAdmin {
        _pause();
    }

    /// @notice Unpause storage operations
    function unpause() external onlyAdmin {
        _unpause();
    }

    /// @notice Store or overwrite a data blob under a given ID
    function storeData(uint256 id, bytes calldata blob)
        external
        whenNotPaused
        onlyWriter
    {
        _dataStore[id] = blob;
        emit DataStored(id, msg.sender, blob.length);
    }

    /// @notice Retrieve a stored data blob by ID
    function getData(uint256 id) external view returns (bytes memory) {
        return _dataStore[id];
    }

    /// @notice Delete a stored data blob
    function deleteData(uint256 id)
        external
        whenNotPaused
        onlyWriter
    {
        delete _dataStore[id];
        emit DataDeleted(id, msg.sender);
    }

    /// @notice Fallback and receive intentionally revert to prevent any unintended execution path
    fallback() external payable {
        revert("DEP: execution disabled");
    }

    receive() external payable {
        revert("DEP: execution disabled");
    }
}
