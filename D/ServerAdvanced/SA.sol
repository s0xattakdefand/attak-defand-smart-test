// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title DataCenterServerSecurity
 * @notice
 *   “Server Advanced” security registry for data center environments.
 *   Tracks servers, their OS and patch levels, and periodic security attestations.
 *
 * Roles:
 *   • DEFAULT_ADMIN_ROLE: can pause/unpause and manage roles.
 *   • SECURITY_OFFICER_ROLE: may register servers, update security info, record attestations, and decommission.
 *
 * Server Lifecycle:
 *   1. Security Officer registers a server with its IP, OS version, and patch level.
 *   2. They update OS or patch levels as needed.
 *   3. They record security attestations (compliant/non-compliant) with timestamps.
 *   4. They decommission servers when retired.
 */
contract DataCenterServerSecurity is AccessControl, Pausable {
    bytes32 public constant SECURITY_OFFICER_ROLE = keccak256("SECURITY_OFFICER_ROLE");

    struct Server {
        address registeredBy;
        string  ipAddress;               // e.g., "192.0.2.10"
        string  osVersion;               // e.g., "Ubuntu 22.04"
        string  patchLevel;              // e.g., "2025-06-15"
        uint256 lastAttestation;         // timestamp of last attestation
        bool    compliant;               // result of last attestation
        bool    exists;
    }

    uint256 private _nextServerId = 1;
    mapping(uint256 => Server) private _servers;
    uint256[] private _allServerIds;

    event ServerRegistered(
        uint256 indexed serverId,
        address indexed by,
        string ipAddress,
        string osVersion,
        string patchLevel
    );
    event ServerUpdated(
        uint256 indexed serverId,
        string newOsVersion,
        string newPatchLevel
    );
    event AttestationRecorded(
        uint256 indexed serverId,
        address indexed by,
        bool compliant,
        uint256 timestamp
    );
    event ServerDecommissioned(uint256 indexed serverId, address indexed by);

    modifier onlyOfficer() {
        require(hasRole(SECURITY_OFFICER_ROLE, msg.sender), "Not a security officer");
        _;
    }

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(SECURITY_OFFICER_ROLE, admin);
    }

    /// @notice Pause all operations in an emergency
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Resume operations
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Register a new server in the data center
    function registerServer(
        string calldata ipAddress,
        string calldata osVersion,
        string calldata patchLevel
    )
        external
        whenNotPaused
        onlyOfficer
        returns (uint256 serverId)
    {
        require(bytes(ipAddress).length > 0, "IP address required");
        require(bytes(osVersion).length > 0, "OS version required");
        require(bytes(patchLevel).length > 0, "Patch level required");

        serverId = _nextServerId++;
        _servers[serverId] = Server({
            registeredBy:     msg.sender,
            ipAddress:        ipAddress,
            osVersion:        osVersion,
            patchLevel:       patchLevel,
            lastAttestation:  0,
            compliant:        false,
            exists:           true
        });
        _allServerIds.push(serverId);

        emit ServerRegistered(serverId, msg.sender, ipAddress, osVersion, patchLevel);
    }

    /// @notice Update a server’s OS version and/or patch level
    function updateServer(
        uint256 serverId,
        string calldata newOsVersion,
        string calldata newPatchLevel
    )
        external
        whenNotPaused
        onlyOfficer
    {
        Server storage s = _servers[serverId];
        require(s.exists, "Server not found");

        if (bytes(newOsVersion).length > 0) {
            s.osVersion = newOsVersion;
        }
        if (bytes(newPatchLevel).length > 0) {
            s.patchLevel = newPatchLevel;
        }

        emit ServerUpdated(serverId, s.osVersion, s.patchLevel);
    }

    /// @notice Record a security attestation for a server
    function recordAttestation(uint256 serverId, bool compliant)
        external
        whenNotPaused
        onlyOfficer
    {
        Server storage s = _servers[serverId];
        require(s.exists, "Server not found");

        s.lastAttestation = block.timestamp;
        s.compliant = compliant;

        emit AttestationRecorded(serverId, msg.sender, compliant, s.lastAttestation);
    }

    /// @notice Decommission a server (mark as no longer managed)
    function decommissionServer(uint256 serverId)
        external
        whenNotPaused
        onlyOfficer
    {
        Server storage s = _servers[serverId];
        require(s.exists, "Server not found");

        s.exists = false;
        emit ServerDecommissioned(serverId, msg.sender);
    }

    /// @notice Retrieve details for a server
    function getServer(uint256 serverId)
        external
        view
        returns (
            address  registeredBy,
            string memory ipAddress,
            string memory osVersion,
            string memory patchLevel,
            uint256  lastAttestation,
            bool     compliant,
            bool     exists
        )
    {
        Server storage s = _servers[serverId];
        require(s.registeredBy != address(0), "Server not found");
        return (
            s.registeredBy,
            s.ipAddress,
            s.osVersion,
            s.patchLevel,
            s.lastAttestation,
            s.compliant,
            s.exists
        );
    }

    /// @notice List all server IDs (including decommissioned ones)
    function listServers() external view returns (uint256[] memory) {
        return _allServerIds;
    }
}
