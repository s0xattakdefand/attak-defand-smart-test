// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title DataCenterGroup
 * @notice
 *   Manages a “Data Center Group” consisting of individual data centers.
 *
 * Roles:
 *   • DEFAULT_ADMIN_ROLE: can add/remove group managers, pause/unpause.
 *   • GROUP_MANAGER_ROLE: can register, update, and revoke data centers.
 *
 * Each Data Center has:
 *   • id            – sequential uint256
 *   • name          – human-readable
 *   • location      – e.g. “Ashburn, VA”
 *   • metadataURI   – off-chain pointer (IPFS, HTTPS JSON)
 *   • exists        – flag for validity
 */
contract DataCenterGroup is AccessControl, Pausable {
    bytes32 public constant GROUP_MANAGER_ROLE = keccak256("GROUP_MANAGER_ROLE");

    struct DataCenter {
        string name;
        string location;
        string metadataURI;
        address registeredBy;
        bool exists;
    }

    uint256 private _nextCenterId = 1;
    mapping(uint256 => DataCenter) private _centers;
    uint256[] private _allCenterIds;

    event GroupManagerAdded(address indexed account);
    event GroupManagerRemoved(address indexed account);
    event DataCenterRegistered(
        uint256 indexed centerId,
        string name,
        string location,
        string metadataURI,
        address indexed registeredBy
    );
    event DataCenterUpdated(
        uint256 indexed centerId,
        string newName,
        string newLocation,
        string newMetadataURI
    );
    event DataCenterRevoked(uint256 indexed centerId);

    modifier onlyManager() {
        require(hasRole(GROUP_MANAGER_ROLE, msg.sender), "DCG: not a group manager");
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

    /// @notice Pause registration and updates
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause registration and updates
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Register a new Data Center
    function registerDataCenter(
        string calldata name,
        string calldata location,
        string calldata metadataURI
    ) external whenNotPaused onlyManager returns (uint256 centerId) {
        require(bytes(name).length > 0, "DCG: name required");
        require(bytes(location).length > 0, "DCG: location required");
        centerId = _nextCenterId++;
        _centers[centerId] = DataCenter({
            name:         name,
            location:     location,
            metadataURI:  metadataURI,
            registeredBy: msg.sender,
            exists:       true
        });
        _allCenterIds.push(centerId);
        emit DataCenterRegistered(centerId, name, location, metadataURI, msg.sender);
    }

    /// @notice Update an existing Data Center’s details
    function updateDataCenter(
        uint256 centerId,
        string calldata newName,
        string calldata newLocation,
        string calldata newMetadataURI
    ) external whenNotPaused onlyManager {
        DataCenter storage dc = _centers[centerId];
        require(dc.exists, "DCG: center not found");
        dc.name = newName;
        dc.location = newLocation;
        dc.metadataURI = newMetadataURI;
        emit DataCenterUpdated(centerId, newName, newLocation, newMetadataURI);
    }

    /// @notice Revoke (remove) a Data Center from the group
    function revokeDataCenter(uint256 centerId) external whenNotPaused onlyManager {
        DataCenter storage dc = _centers[centerId];
        require(dc.exists, "DCG: center not found");
        dc.exists = false;
        emit DataCenterRevoked(centerId);
    }

    /// @notice Fetch details of a Data Center
    function getDataCenter(uint256 centerId)
        external
        view
        returns (
            string memory name,
            string memory location,
            string memory metadataURI,
            address registeredBy,
            bool exists
        )
    {
        DataCenter storage dc = _centers[centerId];
        require(dc.registeredBy != address(0), "DCG: center not found");
        return (dc.name, dc.location, dc.metadataURI, dc.registeredBy, dc.exists);
    }

    /// @notice List all Data Center IDs (including revoked ones)
    function listAllCenterIds() external view returns (uint256[] memory) {
        return _allCenterIds;
    }
}
