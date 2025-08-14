// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Importing OpenZeppelin contracts for security and standard patterns
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Context.sol";

// Smart contract for managing device identities (DevID)
contract DevID is AccessControl, ReentrancyGuard {
    // Define role identifiers
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant DEVICE_ROLE = keccak256("DEVICE_ROLE");

    // Struct to represent a device identity
    struct DeviceIdentity {
        bytes32 devID; // Unique device identifier
        address deviceAddress;
        string name;
        string ipfsHash; // Store device metadata (e.g., specs, certificates) on IPFS
        bool isActive;
        uint256 registrationDate;
    }

    // State variables
    mapping(bytes32 => DeviceIdentity) public devices;
    mapping(address => bytes32) public addressToDevID; // Map device address to DevID
    uint256 public deviceCount;

    // Events for transparency
    event DeviceRegistered(bytes32 indexed devID, address indexed deviceAddress, string name, string ipfsHash, uint256 registrationDate);
    event DeviceDeactivated(bytes32 indexed devID, address indexed deviceAddress);
    event DeviceAuthenticated(bytes32 indexed devID, address indexed deviceAddress, uint256 timestamp);

    // Constructor to set up roles and make deployer the default admin
    constructor() {
        deviceCount = 0;
        // Set up the default admin role for the deployer
        _grantRole(ADMIN_ROLE, _msgSender());
        _setRoleAdmin(ADMIN_ROLE, ADMIN_ROLE); // Admins can manage all roles
        _setRoleAdmin(DEVICE_ROLE, ADMIN_ROLE); // Admins can assign Device role
    }

    // Modifier to restrict actions to active devices
    modifier onlyActiveDevice() {
        bytes32 devID = addressToDevID[_msgSender()];
        require(devices[devID].isActive, "Device is not active or registered");
        _;
    }

    // Function to generate a unique DevID based on device address and metadata
    function generateDevID(address _deviceAddress, string memory _name) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(_deviceAddress, _name));
    }

    // Function to register a new device with a DevID
    function registerDevice(address _deviceAddress, string memory _name, string memory _ipfsHash) external onlyRole(ADMIN_ROLE) nonReentrant {
        require(_deviceAddress != address(0), "Invalid device address");
        require(bytes(_name).length > 0, "Name cannot be empty");
        require(bytes(_ipfsHash).length > 0, "IPFS hash cannot be empty");
        bytes32 devID = generateDevID(_deviceAddress, _name);
        require(!devices[devID].isActive, "Device already registered");

        devices[devID] = DeviceIdentity({
            devID: devID,
            deviceAddress: _deviceAddress,
            name: _name,
            ipfsHash: _ipfsHash,
            isActive: true,
            registrationDate: block.timestamp
        });
        addressToDevID[_deviceAddress] = devID;
        deviceCount++;

        // Grant the Device role to the device
        _grantRole(DEVICE_ROLE, _deviceAddress);

        emit DeviceRegistered(devID, _deviceAddress, _name, _ipfsHash, block.timestamp);
    }

    // Function to deactivate a device
    function deactivateDevice(bytes32 _devID) external onlyRole(ADMIN_ROLE) nonReentrant {
        DeviceIdentity storage device = devices[_devID];
        require(device.isActive, "Device not active or registered");

        device.isActive = false;
        addressToDevID[device.deviceAddress] = bytes32(0); // Clear mapping
        _revokeRole(DEVICE_ROLE, device.deviceAddress);

        emit DeviceDeactivated(_devID, device.deviceAddress);
    }

    // Function for a device to authenticate itself
    function authenticateDevice() external onlyActiveDevice nonReentrant {
        bytes32 devID = addressToDevID[_msgSender()];
        emit DeviceAuthenticated(devID, _msgSender(), block.timestamp);
    }

    // Function to update device metadata
    function updateDeviceMetadata(bytes32 _devID, string memory _ipfsHash) external onlyRole(ADMIN_ROLE) nonReentrant {
        DeviceIdentity storage device = devices[_devID];
        require(device.isActive, "Device not active or registered");
        require(bytes(_ipfsHash).length > 0, "IPFS hash cannot be empty");

        device.ipfsHash = _ipfsHash;
        emit DeviceRegistered(_devID, device.deviceAddress, device.name, _ipfsHash, device.registrationDate);
    }

    // Function to get device details by DevID
    function getDeviceByDevID(bytes32 _devID) external view returns (
        bytes32 devID,
        address deviceAddress,
        string memory name,
        string memory ipfsHash,
        bool isActive,
        uint256 registrationDate
    ) {
        DeviceIdentity storage device = devices[_devID];
        require(device.deviceAddress != address(0), "Device not registered");
        return (
            device.devID,
            device.deviceAddress,
            device.name,
            device.ipfsHash,
            device.isActive,
            device.registrationDate
        );
    }

    // Function to get DevID by device address
    function getDevIDByAddress(address _deviceAddress) external view returns (bytes32) {
        bytes32 devID = addressToDevID[_deviceAddress];
        require(devices[devID].deviceAddress != address(0), "Device not registered");
        return devID;
    }

    // Function to check if a device has the Device role
    function hasDeviceRole(address _deviceAddress) external view returns (bool) {
        return hasRole(DEVICE_ROLE, _deviceAddress);
    }
}

// Notes:
// - This contract uses OpenZeppelin's AccessControl and ReentrancyGuard for secure role-based access control and protection against reentrancy attacks.
// - IPFS hash stores device metadata (e.g., specifications, certificates) off-chain to reduce gas costs.
// - Two roles are defined: ADMIN_ROLE (manages devices) and DEVICE_ROLE (assigned to registered devices).
// - DevID is generated deterministically using keccak256 on device address and name.
// - Only admins can register, deactivate, or update devices, ensuring controlled access.
// - Devices can authenticate themselves, emitting an event for off-chain verification.
// - Events ensure transparency and auditability, enabling integration with off-chain IoT systems.
// - Source code should be audited before deployment, preferably 2 weeks prior to mainnet use.
// - Recommended to store source code on GitHub with a specific commit hash for audit purposes.