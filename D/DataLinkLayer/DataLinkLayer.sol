// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title PhysicalLayerRegistry
 * @notice
 *   Models the Physical Layer of the TCP/IP stack (e.g., Ethernet interfaces) per NIST SP 800-113:
 *   • ADMIN_ROLE manages roles and may pause/unpause operations.
 *   • DEVICE_ROLE may register and update physical network interfaces.
 *
 * Each NetworkInterface:
 *   • id           – sequential uint256
 *   • macAddress   – 6-byte MAC address
 *   • mediumType   – e.g. "Ethernet", "WiFi", "Fiber"
 *   • description  – optional human‐readable info (location, port, etc.)
 *   • active       – status flag
 */
contract PhysicalLayerRegistry is AccessControl, Pausable {
    bytes32 public constant DEVICE_ROLE = keccak256("DEVICE_ROLE");

    struct NetworkInterface {
        bytes6  macAddress;
        string  mediumType;
        string  description;
        bool    active;
        address registeredBy;
    }

    uint256 private _nextIfId = 1;
    mapping(uint256 => NetworkInterface) private _interfaces;
    uint256[] private _allIfIds;

    event DeviceRoleGranted(address indexed account);
    event DeviceRoleRevoked(address indexed account);

    event InterfaceRegistered(
        uint256 indexed ifId,
        bytes6   macAddress,
        string   mediumType,
        string   description,
        address  registeredBy
    );
    event InterfaceUpdated(
        uint256 indexed ifId,
        string   newDescription,
        bool     active
    );
    event InterfaceDeactivated(uint256 indexed ifId);

    modifier onlyAdmin() {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "PLR: not admin");
        _;
    }
    modifier onlyDevice() {
        require(hasRole(DEVICE_ROLE, msg.sender), "PLR: not device role");
        _;
    }

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    /// @notice Grant DEVICE_ROLE to an account
    function grantDeviceRole(address account) external onlyAdmin {
        grantRole(DEVICE_ROLE, account);
        emit DeviceRoleGranted(account);
    }

    /// @notice Revoke DEVICE_ROLE from an account
    function revokeDeviceRole(address account) external onlyAdmin {
        revokeRole(DEVICE_ROLE, account);
        emit DeviceRoleRevoked(account);
    }

    /// @notice Pause registry operations
    function pause() external onlyAdmin {
        _pause();
    }

    /// @notice Unpause registry operations
    function unpause() external onlyAdmin {
        _unpause();
    }

    /// @notice Register a new physical network interface
    function registerInterface(
        bytes6 macAddress,
        string calldata mediumType,
        string calldata description
    )
        external
        whenNotPaused
        onlyDevice
        returns (uint256 ifId)
    {
        require(bytes(mediumType).length > 0, "PLR: mediumType required");
        ifId = _nextIfId++;
        _interfaces[ifId] = NetworkInterface({
            macAddress:   macAddress,
            mediumType:   mediumType,
            description:  description,
            active:       true,
            registeredBy: msg.sender
        });
        _allIfIds.push(ifId);
        emit InterfaceRegistered(ifId, macAddress, mediumType, description, msg.sender);
    }

    /// @notice Update description or activation status of an interface
    function updateInterface(
        uint256 ifId,
        string calldata newDescription,
        bool active
    )
        external
        whenNotPaused
        onlyDevice
    {
        NetworkInterface storage ni = _interfaces[ifId];
        require(ni.registeredBy != address(0), "PLR: interface not found");
        ni.description = newDescription;
        ni.active      = active;
        emit InterfaceUpdated(ifId, newDescription, active);
    }

    /// @notice Deactivate (disable) an interface
    function deactivateInterface(uint256 ifId)
        external
        whenNotPaused
        onlyAdmin
    {
        NetworkInterface storage ni = _interfaces[ifId];
        require(ni.registeredBy != address(0), "PLR: interface not found");
        ni.active = false;
        emit InterfaceDeactivated(ifId);
    }

    /// @notice Retrieve interface details
    function getInterface(uint256 ifId)
        external
        view
        returns (
            bytes6  macAddress,
            string memory mediumType,
            string memory description,
            bool    active,
            address registeredBy
        )
    {
        NetworkInterface storage ni = _interfaces[ifId];
        require(ni.registeredBy != address(0), "PLR: interface not found");
        return (ni.macAddress, ni.mediumType, ni.description, ni.active, ni.registeredBy);
    }

    /// @notice List all interface IDs
    function listInterfaceIds() external view returns (uint256[] memory) {
        return _allIfIds;
    }
}
