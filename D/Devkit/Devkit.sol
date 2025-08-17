// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Importing OpenZeppelin contracts for security and standard patterns
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Context.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

// Smart contract for a device development kit (Devkit) managing identities, roles, and interactions
contract Devkit is AccessControl, ReentrancyGuard {
    using SafeERC20 for IERC20;

    // Define role identifiers
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant SENDER_ROLE = keccak256("SENDER_ROLE");
    bytes32 public constant RECEIVER_ROLE = keccak256("RECEIVER_ROLE");

    // Struct to represent a device identity
    struct Device {
        bytes32 devID; // Unique device identifier
        address deviceAddress;
        string name;
        string ipfsHash; // Store device metadata (e.g., specs, certificates) on IPFS
        bool isActive;
        uint256 registrationDate;
    }

    // Struct to represent a device-to-device interaction
    struct Interaction {
        uint256 id;
        address sender;
        address receiver;
        string action; // e.g., "sendMessage", "executeCommand"
        uint256 tokenAmount; // Optional token transfer amount
        string ipfsHash; // Store interaction details on IPFS
        uint256 timestamp;
    }

    // State variables
    mapping(bytes32 => Device) public devices;
    mapping(address => bytes32) public addressToDevID; // Map device address to DevID
    mapping(uint256 => Interaction) public interactions;
    uint256 public deviceCount;
    uint256 public interactionCount;
    IERC20 public token; // Optional ERC20 token for D2D payments

    // Events for transparency
    event DeviceRegistered(bytes32 indexed devID, address indexed deviceAddress, string name, string ipfsHash, bytes32 role, uint256 registrationDate);
    event DeviceDeactivated(bytes32 indexed devID, address indexed deviceAddress);
    event DeviceAuthenticated(bytes32 indexed devID, address indexed deviceAddress, uint256 timestamp);
    event InteractionExecuted(uint256 indexed interactionId, address indexed sender, address indexed receiver, string action, uint256 tokenAmount, string ipfsHash, uint256 timestamp);

    // Constructor to set up roles and optionally set an ERC20 token
    constructor(address _tokenAddress) {
        deviceCount = 0;
        interactionCount = 0;
        // Set up the default admin role for the deployer
        _grantRole(ADMIN_ROLE, _msgSender());
        _setRoleAdmin(ADMIN_ROLE, ADMIN_ROLE); // Admins can manage all roles
        _setRoleAdmin(SENDER_ROLE, ADMIN_ROLE); // Admins can assign Sender role
        _setRoleAdmin(RECEIVER_ROLE, ADMIN_ROLE); // Admins can assign Receiver role

        // Set token if provided
        if (_tokenAddress != address(0)) {
            token = IERC20(_tokenAddress);
        }
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
        require(_role == ADMIN_ROLE || _role == SENDER_ROLE || _role == RECEIVER_ROLE, "Invalid role");
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
        if (hasRole(SENDER_ROLE, device.deviceAddress)) {
            _revokeRole(SENDER_ROLE, device.deviceAddress);
        }
        if (hasRole(RECEIVER_ROLE, device.deviceAddress)) {
            _revokeRole(RECEIVER_ROLE, device.deviceAddress);
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
        } else if (hasRole(SENDER_ROLE, device.deviceAddress)) {
            deviceRole = SENDER_ROLE;
        } else if (hasRole(RECEIVER_ROLE, device.deviceAddress)) {
            deviceRole = RECEIVER_ROLE;
        } else {
            deviceRole = bytes32(0); // No role
        }

        device.ipfsHash = _ipfsHash;
        emit DeviceRegistered(_devID, device.deviceAddress, device.name, _ipfsHash, deviceRole, device.registrationDate);
    }

    // Function for a sender device to execute an interaction with a receiver device
    function executeInteraction(address _receiver, string memory _action, uint256 _tokenAmount, string memory _ipfsHash) external onlyActiveDevice nonReentrant {
        require(hasRole(SENDER_ROLE, _msgSender()), "Caller must have Sender role");
        require(devices[addressToDevID[_receiver]].isActive, "Receiver device not active or registered");
        require(hasRole(RECEIVER_ROLE, _receiver) || hasRole(ADMIN_ROLE, _receiver), "Receiver must have Receiver or Admin role");
        require(bytes(_action).length > 0, "Action cannot be empty");
        require(bytes(_ipfsHash).length > 0, "IPFS hash cannot be empty");
        if (_tokenAmount > 0) {
            require(address(token) != address(0), "Token not configured");
            require(token.balanceOf(_msgSender()) >= _tokenAmount, "Insufficient token balance");
        }

        // Record the interaction
        uint256 interactionId = interactionCount;
        interactions[interactionId] = Interaction({
            id: interactionId,
            sender: _msgSender(),
            receiver: _receiver,
            action: _action,
            tokenAmount: _tokenAmount,
            ipfsHash: _ipfsHash,
            timestamp: block.timestamp
        });
        interactionCount++;

        // Perform token transfer if applicable
        if (_tokenAmount > 0) {
            token.safeTransferFrom(_msgSender(), _receiver, _tokenAmount);
        }

        emit InteractionExecuted(interactionId, _msgSender(), _receiver, _action, _tokenAmount, _ipfsHash, block.timestamp);
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
        } else if (hasRole(SENDER_ROLE, device.deviceAddress)) {
            deviceRole = SENDER_ROLE;
        } else if (hasRole(RECEIVER_ROLE, device.deviceAddress)) {
            deviceRole = RECEIVER_ROLE;
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

    // Function to get interaction details
    function getInteraction(uint256 _interactionId) external view returns (
        uint256 id,
        address sender,
        address receiver,
        string memory action,
        uint256 tokenAmount,
        string memory ipfsHash,
        uint256 timestamp
    ) {
        Interaction storage interaction = interactions[_interactionId];
        require(interaction.sender != address(0), "Interaction does not exist");
        return (
            interaction.id,
            interaction.sender,
            interaction.receiver,
            interaction.action,
            interaction.tokenAmount,
            interaction.ipfsHash,
            interaction.timestamp
        );
    }

    // Function to check if a device has a specific role
    function hasDeviceRole(address _deviceAddress, bytes32 _role) external view returns (bool) {
        return hasRole(_role, _deviceAddress);
    }
}

// Notes:
// - This contract uses OpenZeppelin's AccessControl, ReentrancyGuard, and SafeERC20 for secure role-based access control, protection against reentrancy, and safe token transfers.
// - IPFS hash stores device and interaction metadata (e.g., device specs, action details) off-chain to reduce gas costs.
// - Three roles are defined: ADMIN_ROLE (manages devices), SENDER_ROLE (initiates interactions), and RECEIVER_ROLE (receives interactions).
// - DevID is generated deterministically using keccak256 on device address and name.
// - Supports device registration, authentication, and D2D interactions with optional ERC20 token transfers.
// - Events ensure transparency and auditability, enabling integration with off-chain IoT systems.
// - Source code should be audited before deployment, preferably 2 weeks prior to mainnet use.
// - Recommended to store source code on GitHub with a specific commit hash for audit purposes.