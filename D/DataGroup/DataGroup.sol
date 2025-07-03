// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title DataGroup
 * @notice
 *   Manages collections (“groups”) of data assets on-chain.
 *   • ADMIN_ROLE can pause/unpause and manage roles.
 *   • GROUP_MANAGER_ROLE may create groups, add/remove assets, and delete groups.
 *
 * A Data Group has:
 *   • id          – sequential uint256
 *   • name        – human-readable
 *   • description – optional details
 *   • assets      – list of asset IDs (uint256) in the group
 *   • exists      – flag for validity
 */
contract DataGroup is AccessControl, Pausable {
    bytes32 public constant GROUP_MANAGER_ROLE = keccak256("GROUP_MANAGER_ROLE");

    struct Group {
        string   name;
        string   description;
        uint256[] assets;
        bool     exists;
    }

    uint256 private _nextGroupId = 1;
    mapping(uint256 => Group) private _groups;
    uint256[] private _allGroupIds;

    event GroupManagerAdded(address indexed account);
    event GroupManagerRemoved(address indexed account);

    event GroupCreated(
        uint256 indexed groupId,
        string name,
        string description,
        address indexed creator
    );
    event AssetAddedToGroup(uint256 indexed groupId, uint256 indexed assetId);
    event AssetRemovedFromGroup(uint256 indexed groupId, uint256 indexed assetId);
    event GroupDeleted(uint256 indexed groupId);

    modifier onlyManager() {
        require(hasRole(GROUP_MANAGER_ROLE, msg.sender), "DataGroup: not a manager");
        _;
    }

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(GROUP_MANAGER_ROLE, admin);
    }

    /// @notice Grant GROUP_MANAGER_ROLE to an account
    function addGroupManager(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(GROUP_MANAGER_ROLE, account);
        emit GroupManagerAdded(account);
    }

    /// @notice Revoke GROUP_MANAGER_ROLE from an account
    function removeGroupManager(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(GROUP_MANAGER_ROLE, account);
        emit GroupManagerRemoved(account);
    }

    /// @notice Pause operations
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause operations
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Create a new data group
    function createGroup(string calldata name, string calldata description)
        external
        whenNotPaused
        onlyManager
        returns (uint256 groupId)
    {
        require(bytes(name).length > 0, "DataGroup: name required");
        groupId = _nextGroupId++;
        Group storage g = _groups[groupId];
        g.name = name;
        g.description = description;
        g.exists = true;
        _allGroupIds.push(groupId);
        emit GroupCreated(groupId, name, description, msg.sender);
    }

    /// @notice Add an asset to a group
    function addAsset(uint256 groupId, uint256 assetId)
        external
        whenNotPaused
        onlyManager
    {
        Group storage g = _groups[groupId];
        require(g.exists, "DataGroup: group not found");
        // Prevent duplicates
        for (uint i = 0; i < g.assets.length; i++) {
            require(g.assets[i] != assetId, "DataGroup: asset already in group");
        }
        g.assets.push(assetId);
        emit AssetAddedToGroup(groupId, assetId);
    }

    /// @notice Remove an asset from a group
    function removeAsset(uint256 groupId, uint256 assetId)
        external
        whenNotPaused
        onlyManager
    {
        Group storage g = _groups[groupId];
        require(g.exists, "DataGroup: group not found");
        uint len = g.assets.length;
        for (uint i = 0; i < len; i++) {
            if (g.assets[i] == assetId) {
                g.assets[i] = g.assets[len - 1];
                g.assets.pop();
                emit AssetRemovedFromGroup(groupId, assetId);
                return;
            }
        }
        revert("DataGroup: asset not in group");
    }

    /// @notice Delete a group and its asset list
    function deleteGroup(uint256 groupId)
        external
        whenNotPaused
        onlyManager
    {
        Group storage g = _groups[groupId];
        require(g.exists, "DataGroup: group not found");
        delete _groups[groupId];
        // remove from _allGroupIds
        uint len = _allGroupIds.length;
        for (uint i = 0; i < len; i++) {
            if (_allGroupIds[i] == groupId) {
                _allGroupIds[i] = _allGroupIds[len - 1];
                _allGroupIds.pop();
                break;
            }
        }
        emit GroupDeleted(groupId);
    }

    /// @notice Get group details
    function getGroup(uint256 groupId)
        external
        view
        returns (
            string memory name,
            string memory description,
            uint256[] memory assets,
            bool exists
        )
    {
        Group storage g = _groups[groupId];
        require(g.exists, "DataGroup: group not found");
        return (g.name, g.description, g.assets, g.exists);
    }

    /// @notice List all group IDs
    function listGroupIds() external view returns (uint256[] memory) {
        return _allGroupIds;
    }
}
