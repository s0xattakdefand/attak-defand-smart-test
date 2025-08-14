// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Importing OpenZeppelin contracts for security and standard patterns
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Context.sol";

// Smart contract for managing device roles in a decentralized system
contract DeviceRole is AccessControl, ReentrancyGuard {
    // Define role identifiers
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant CONTROLLER_ROLE = keccak256("CONTROLLER_ROLE");
    bytes32 public constant SENSOR_ROLE = keccak256("SENSOR_ROLE");

    // Struct to represent a device
    struct Device {
        address deviceAddress;
        string name;
        string ipfsHash; // Store device metadata (e.g., specs, role details) on IPFS
        bool isActive;
        uint256 registrationDate;
    }

    // State variables
    mapping(address => Device) public devices;
    uint256 public deviceCount;

    // Events for transparency
    event DeviceRegistered(address indexed deviceAddress, string name, string ipfsHash, bytes32 role, uint256 registrationDate);
    event DeviceRoleUpdated(address indexed deviceAddress, bytes32 oldRole, bytes32 newRole, string ipfsHash);
    event DeviceDeactivated(address indexed deviceAddress);
    event ActionExecuted(address indexed deviceAddress, string action, string ipfsHash);

    // Constructor to set up roles and make deployer the default admin
    constructor() {
        deviceCount = 0;
        // Set up the default admin role for the deployer
        _grantRole(ADMIN_ROLE, _msgSender());
        _setRoleAdmin(ADMIN_ROLE, ADMIN_ROLE); // Admins can manage all roles
        _setRoleAdmin(CONTROLLER_ROLE, ADMIN_ROLE); // Admins can assign Controller role
        _setRoleAdmin(SENSOR_ROLE, ADMIN_ROLE); // Admins can assign Sensor role
    }

    // Modifier to restrict actions to active devices
    modifier onlyActiveDevice() {
        require(devices[_msgSender()].isActive, "Device is not active or registered");
        _;
    }

    // Function to register a new device with a role
    function registerDevice(address _deviceAddress, string memory _name, string memory _ipfsHash, bytes32 _role) external onlyRole(ADMIN_ROLE) nonReentrant {
        require(_deviceAddress != address(0), "Invalid device address");
        require(!devices[_deviceAddress].isActive, "Device already registered");
        require(bytes(_name).length > 0, "Name cannot be empty");
        require(bytes(_ipfsHash).length > 0, "IPFS hash cannot be empty");
        require(_role == ADMIN_ROLE || _role == CONTROLLER_ROLE || _role == SENSOR_ROLE, "Invalid role");

        devices[_deviceAddress] = Device({
            deviceAddress: _deviceAddress,
            name: _name,
            ipfsHash: _ipfsHash,
            isActive: true,
            registrationDate: block.timestamp
        });
        deviceCount++;

        // Grant the specified role to the device
        _grantRole(_role, _deviceAddress);

        emit DeviceRegistered(_deviceAddress, _name, _ipfsHash, _role, block.timestamp);
    }

    // Function to update a device's role
    function updateDeviceRole(address _deviceAddress, bytes32 _newRole, string memory _ipfsHash) external onlyRole(ADMIN_ROLE) nonReentrant {
        require(devices[_deviceAddress].isActive, "Device not active or registered");
        require(bytes(_ipfsHash).length > 0, "IPFS hash cannot be empty");
        require(_newRole == ADMIN_ROLE || _newRole == CONTROLLER_ROLE || _newRole == SENSOR_ROLE, "Invalid role");

        // Get the current role
        bytes32 oldRole;
        if (hasRole(ADMIN_ROLE, _deviceAddress)) {
            oldRole = ADMIN_ROLE;
        } else if (hasRole(CONTROLLER_ROLE, _deviceAddress)) {
            oldRole = CONTROLLER_ROLE;
        } else if (hasRole(SENSOR_ROLE, _deviceAddress)) {
            oldRole = SENSOR_ROLE;
        } else {
            revert("Device has no role");
        }

        // Revoke old role and grant new role
        _revokeRole(oldRole, _deviceAddress);
        _grantRole(_newRole, _deviceAddress);

        // Update IPFS hash
        devices[_deviceAddress].ipfsHash = _ipfsHash;

        emit DeviceRoleUpdated(_deviceAddress, oldRole, _newRole, _ipfsHash);
    }

    // Function to deactivate a device
    function deactivateDevice(address _deviceAddress) external onlyRole(ADMIN_ROLE) nonReentrant {
        require(devices[_deviceAddress].isActive, "Device not active or registered");

        devices[_deviceAddress].isActive = false;

        // Revoke all roles
        if (hasRole(ADMIN_ROLE, _deviceAddress)) {
            _revokeRole(ADMIN_ROLE, _deviceAddress);
        }
        if (hasRole(CONTROLLER_ROLE, _deviceAddress)) {
            _revokeRole(CONTROLLER_ROLE, _deviceAddress);
        }
        if (hasRole(SENSOR_ROLE, _deviceAddress)) {
            _revokeRole(SENSOR_ROLE, _deviceAddress);
        }

        emit DeviceDeactivated(_deviceAddress);
    }

    // Function for devices to execute role-specific actions
    function executeAction(string memory _action, string memory _ipfsHash) external onlyActiveDevice nonReentrant {
        require(bytes(_action).length > 0, "Action cannot be empty");
        require(bytes(_ipfsHash).length > 0, "IPFS hash cannot be empty");

        // Example role-based restrictions
        if (hasRole(SENSOR_ROLE, _msgSender())) {
            require(keccak256(abi.encodePacked(_action)) == keccak256(abi.encodePacked("reportData")), "Sensor can only report data");
        } else if (hasRole(CONTROLLER_ROLE, _msgSender())) {
            require(
                keccak256(abi.encodePacked(_action)) == keccak256(abi.encodePacked("controlDevice")) ||
                keccak256(abi.encodePacked(_action)) == keccak256(abi.encodePacked("configure")),
                "Controller can only control or configure"
            );
        }
        // Admins can perform any action

        emit ActionExecuted(_msgSender(), _action, _ipfsHash);
    }

    // Function to get device details
    function getDevice(address _deviceAddress) external view returns (
        address deviceAddress,
        string memory name,
        string memory ipfsHash,
        bool isActive,
        uint256 registrationDate,
        bytes32 role
    ) {
        Device storage device = devices[_deviceAddress];
        require(device.deviceAddress != address(0), "Device not registered");

        bytes32 deviceRole;
        if (hasRole(ADMIN_ROLE, _deviceAddress)) {
            deviceRole = ADMIN_ROLE;
        } else if (hasRole(CONTROLLER_ROLE, _deviceAddress)) {
            deviceRole = CONTROLLER_ROLE;
        } else if (hasRole(SENSOR_ROLE, _deviceAddress)) {
            deviceRole = SENSOR_ROLE;
        } else {
            deviceRole = bytes32(0); // No role
        }

        return (
            device.deviceAddress,
            device.name,
            device.ipfsHash,
            device.isActive,
            device.registrationDate,
            deviceRole
        );
    }

    // Function to check if a device has a specific role
    function hasDeviceRole(address _deviceAddress, bytes32 _role) external view returns (bool) {
        return hasRole(_role, _deviceAddress);
    }
}

// Notes:
// - This contract uses OpenZeppelin's AccessControl and ReentrancyGuard for secure role-based access control and protection against reentrancy attacks.
// - IPFS hash stores device metadata (e.g., specifications, role details) off-chain to reduce gas costs.
// - Three roles are defined: ADMIN_ROLE (manages devices), CONTROLLER_ROLE (controls devices), and SENSOR_ROLE (reports data).
// - Only admins can register, update, or deactivate devices, ensuring controlled access.
// - Devices can execute role-specific actions (e.g., sensors report data, controllers configure devices).
// - Events ensure transparency and auditability, enabling integration with off-chain IoT systems.
// - Source code should be audited before deployment, preferably 2 weeks prior to mainnet use.
// - Recommended to store source code on GitHub with a specific commit hash for audit purposes.