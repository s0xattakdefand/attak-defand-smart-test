// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Importing OpenZeppelin contracts for security and standard patterns
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Context.sol";

// Smart contract for DevOps automation in device management
contract DevOps is AccessControl, ReentrancyGuard {
    // Define role identifiers
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant DEVELOPER_ROLE = keccak256("DEVELOPER_ROLE");
    bytes32 public constant DEVICE_ROLE = keccak256("DEVICE_ROLE");

    // Struct to represent a device identity
    struct Device {
        bytes32 devID; // Unique device identifier
        address deviceAddress;
        string name;
        string ipfsHash; // Store device metadata (e.g., specs, firmware version) on IPFS
        bool isActive;
        uint256 registrationDate;
    }

    // Struct to represent a deployment (e.g., firmware update, configuration change)
    struct Deployment {
        uint256 id;
        bytes32 devID; // Device targeted for deployment
        string deploymentType; // e.g., "firmwareUpdate", "configChange"
        string ipfsHash; // Store deployment details (e.g., firmware binary, config) on IPFS
        address deployer; // Developer who initiated the deployment
        uint256 timestamp;
        bool isApproved; // Approval status for deployment
    }

    // State variables
    mapping(bytes32 => Device) public devices;
    mapping(address => bytes32) public addressToDevID; // Map device address to DevID
    mapping(uint256 => Deployment) public deployments;
    uint256 public deviceCount;
    uint256 public deploymentCount;

    // Events for transparency and auditability
    event DeviceRegistered(bytes32 indexed devID, address indexed deviceAddress, string name, string ipfsHash, bytes32 role, uint256 registrationDate);
    event DeviceDeactivated(bytes32 indexed devID, address indexed deviceAddress);
    event DeviceAuthenticated(bytes32 indexed devID, address indexed deviceAddress, uint256 timestamp);
    event DeploymentProposed(uint256 indexed deploymentId, bytes32 indexed devID, string deploymentType, string ipfsHash, address indexed deployer, uint256 timestamp);
    event DeploymentApproved(uint256 indexed deploymentId, bytes32 indexed devID, address indexed approver, uint256 timestamp);
    event DeploymentExecuted(uint256 indexed deploymentId, bytes32 indexed devID, address indexed executor, uint256 timestamp);

    // Constructor to set up roles
    constructor() {
        deviceCount = 0;
        deploymentCount = 0;
        // Set up the default admin role for the deployer
        _grantRole(ADMIN_ROLE, _msgSender());
        _setRoleAdmin(ADMIN_ROLE, ADMIN_ROLE); // Admins can manage all roles
        _setRoleAdmin(DEVELOPER_ROLE, ADMIN_ROLE); // Admins can assign Developer role
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

    // Function to register a new device with a DevID and role
    function registerDevice(address _deviceAddress, string memory _name, string memory _ipfsHash, bytes32 _role) external onlyRole(ADMIN_ROLE) nonReentrant {
        require(_deviceAddress != address(0), "Invalid device address");
        require(bytes(_name).length > 0, "Name cannot be empty");
        require(bytes(_ipfsHash).length > 0, "IPFS hash cannot be empty");
        require(_role == ADMIN_ROLE || _role == DEVELOPER_ROLE || _role == DEVICE_ROLE, "Invalid role");
        bytes32 devID = generateDevID(_deviceAddress, _name);
        require(!devices[devID].isActive, "Device already registered");

        devices[devID] = Device({
            devID: devID,
            deviceAddress: _deviceAddress,
            name: _name,
            ipfsHash: _ipfsHash,
            isActive: true,
            registrationDate: block.timestamp
        });
        addressToDevID[_deviceAddress] = devID;
        deviceCount++;

        // Grant the specified role to the device
        _grantRole(_role, _deviceAddress);

        emit DeviceRegistered(devID, _deviceAddress, _name, _ipfsHash, _role, block.timestamp);
    }

    // Function to deactivate a device
    function deactivateDevice(bytes32 _devID) external onlyRole(ADMIN_ROLE) nonReentrant {
        Device storage device = devices[_devID];
        require(device.isActive, "Device not active or registered");

        device.isActive = false;
        addressToDevID[device.deviceAddress] = bytes32(0); // Clear mapping

        // Revoke all roles
        if (hasRole(ADMIN_ROLE, device.deviceAddress)) {
            _revokeRole(ADMIN_ROLE, device.deviceAddress);
        }
        if (hasRole(DEVELOPER_ROLE, device.deviceAddress)) {
            _revokeRole(DEVELOPER_ROLE, device.deviceAddress);
        }
        if (hasRole(DEVICE_ROLE, device.deviceAddress)) {
            _revokeRole(DEVICE_ROLE, device.deviceAddress);
        }

        emit DeviceDeactivated(_devID, device.deviceAddress);
    }

    // Function for a device to authenticate itself
    function authenticateDevice() external onlyActiveDevice nonReentrant {
        bytes32 devID = addressToDevID[_msgSender()];
        emit DeviceAuthenticated(devID, _msgSender(), block.timestamp);
    }

    // Function to update device metadata
    function updateDeviceMetadata(bytes32 _devID, string memory _ipfsHash) external onlyRole(ADMIN_ROLE) nonReentrant {
        Device storage device = devices[_devID];
        require(device.isActive, "Device not active or registered");
        require(bytes(_ipfsHash).length > 0, "IPFS hash cannot be empty");

        // Determine the current role
        bytes32 deviceRole;
        if (hasRole(ADMIN_ROLE, device.deviceAddress)) {
            deviceRole = ADMIN_ROLE;
        } else if (hasRole(DEVELOPER_ROLE, device.deviceAddress)) {
            deviceRole = DEVELOPER_ROLE;
        } else if (hasRole(DEVICE_ROLE, device.deviceAddress)) {
            deviceRole = DEVICE_ROLE;
        } else {
            deviceRole = bytes32(0); // No role
        }

        device.ipfsHash = _ipfsHash;
        emit DeviceRegistered(_devID, device.deviceAddress, device.name, _ipfsHash, deviceRole, device.registrationDate);
    }

    // Function for a developer to propose a deployment (e.g., firmware update)
    function proposeDeployment(bytes32 _devID, string memory _deploymentType, string memory _ipfsHash) external onlyRole(DEVELOPER_ROLE) nonReentrant {
        require(devices[_devID].isActive, "Device not active or registered");
        require(bytes(_deploymentType).length > 0, "Deployment type cannot be empty");
        require(bytes(_ipfsHash).length > 0, "IPFS hash cannot be empty");

        uint256 deploymentId = deploymentCount;
        deployments[deploymentId] = Deployment({
            id: deploymentId,
            devID: _devID,
            deploymentType: _deploymentType,
            ipfsHash: _ipfsHash,
            deployer: _msgSender(),
            timestamp: block.timestamp,
            isApproved: false
        });
        deploymentCount++;

        emit DeploymentProposed(deploymentId, _devID, _deploymentType, _ipfsHash, _msgSender(), block.timestamp);
    }

    // Function for an admin to approve a deployment
    function approveDeployment(uint256 _deploymentId) external onlyRole(ADMIN_ROLE) nonReentrant {
        Deployment storage deployment = deployments[_deploymentId];
        require(deployment.deployer != address(0), "Deployment does not exist");
        require(!deployment.isApproved, "Deployment already approved");

        deployment.isApproved = true;
        emit DeploymentApproved(_deploymentId, deployment.devID, _msgSender(), block.timestamp);
    }

    // Function for a developer to execute an approved deployment
    function executeDeployment(uint256 _deploymentId) external onlyRole(DEVELOPER_ROLE) nonReentrant {
        Deployment storage deployment = deployments[_deploymentId];
        require(deployment.deployer != address(0), "Deployment does not exist");
        require(deployment.isApproved, "Deployment not approved");
        require(devices[deployment.devID].isActive, "Device not active or registered");

        // Mark deployment as executed by emitting an event
        // Actual deployment (e.g., firmware update) occurs off-chain, referenced by IPFS hash
        emit DeploymentExecuted(_deploymentId, deployment.devID, _msgSender(), block.timestamp);
    }

    // Function to get device details by DevID
    function getDeviceByDevID(bytes32 _devID) external view returns (
        bytes32 devID,
        address deviceAddress,
        string memory name,
        string memory ipfsHash,
        bool isActive,
        uint256 registrationDate,
        bytes32 role
    ) {
        Device storage device = devices[_devID];
        require(device.deviceAddress != address(0), "Device not registered");

        bytes32 deviceRole;
        if (hasRole(ADMIN_ROLE, device.deviceAddress)) {
            deviceRole = ADMIN_ROLE;
        } else if (hasRole(DEVELOPER_ROLE, device.deviceAddress)) {
            deviceRole = DEVELOPER_ROLE;
        } else if (hasRole(DEVICE_ROLE, device.deviceAddress)) {
            deviceRole = DEVICE_ROLE;
        } else {
            deviceRole = bytes32(0); // No role
        }

        return (
            device.devID,
            device.deviceAddress,
            device.name,
            device.ipfsHash,
            device.isActive,
            device.registrationDate,
            deviceRole
        );
    }

    // Function to get DevID by device address
    function getDevIDByAddress(address _deviceAddress) external view returns (bytes32) {
        bytes32 devID = addressToDevID[_deviceAddress];
        require(devices[devID].deviceAddress != address(0), "Device not registered");
        return devID;
    }

    // Function to get deployment details
    function getDeployment(uint256 _deploymentId) external view returns (
        uint256 id,
        bytes32 devID,
        string memory deploymentType,
        string memory ipfsHash,
        address deployer,
        uint256 timestamp,
        bool isApproved
    ) {
        Deployment storage deployment = deployments[_deploymentId];
        require(deployment.deployer != address(0), "Deployment does not exist");
        return (
            deployment.id,
            deployment.devID,
            deployment.deploymentType,
            deployment.ipfsHash,
            deployment.deployer,
            deployment.timestamp,
            deployment.isApproved
        );
    }

    // Function to check if an address has a specific role
    function hasDeviceRole(address _deviceAddress, bytes32 _role) external view returns (bool) {
        return hasRole(_role, _deviceAddress);
    }
}

// Notes:
// - This contract uses OpenZeppelin's AccessControl and ReentrancyGuard for secure role-based access control and protection against reentrancy attacks.
// - IPFS hash stores device and deployment metadata (e.g., firmware binaries, configurations) off-chain to reduce gas costs (Web0).
// - Three roles are defined: ADMIN_ROLE (manages devices and approves deployments), DEVELOPER_ROLE (proposes and executes deployments), and DEVICE_ROLE (assigned to devices).
// - DevID is generated deterministically using keccak256 on device address and name.
// - Supports device registration, authentication, and automated deployment workflows with propose-approve-execute stages.
// - Events ensure transparency and auditability, enabling integration with off-chain DevOps tools (Web8).
// - Source code should be audited before deployment, preferably 2 weeks prior to mainnet use (Webisoft, 2025).
// - Recommended to store source code on GitHub with a specific commit hash for audit purposes.