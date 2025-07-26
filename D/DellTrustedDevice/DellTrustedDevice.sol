// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// DellTrustedDevice contract for device integrity verification and event logging
contract DellTrustedDevice {
    // Contract owner (e.g., enterprise IT administrator)
    address public owner;

    // Enum to represent verification status
    enum VerificationStatus { Pending, Passed, Failed }

    // Structure to store device metadata
    struct Device {
        bytes32 deviceId; // Unique identifier (e.g., Service Tag hash)
        address manager; // Address of the device manager
        bytes32 firmwareHash; // Hash of firmware (e.g., BIOS or Intel ME)
        VerificationStatus status; // Current verification status
        uint256 registeredAt; // Timestamp when device was registered
        uint256 lastVerifiedAt; // Timestamp of last verification
        bool exists; // Flag to check if device exists
    }

    // Structure to store security events (Indicators of Attack)
    struct SecurityEvent {
        bytes32 eventId; // Unique event identifier
        bytes32 deviceId; // Associated device ID
        string description; // Description of the event (e.g., "Unauthorized BIOS change")
        uint256 timestamp; // Timestamp of the event
    }

    // Mapping to store devices by device ID
    mapping(bytes32 => Device) public devices;

    // Mapping to store security events by event ID
    mapping(bytes32 => SecurityEvent) public securityEvents;

    // Mapping to store authorized verifiers (e.g., IT admins or SIEM systems)
    mapping(address => bool) public verifiers;

    // Event emitted when a device is registered
    event DeviceRegistered(bytes32 indexed deviceId, address indexed manager, bytes32 firmwareHash, uint256 timestamp);

    // Event emitted when a device is verified
    event DeviceVerified(bytes32 indexed deviceId, VerificationStatus status, bytes32 firmwareHash, uint256 timestamp);

    // Event emitted when a security event is logged
    event SecurityEventLogged(bytes32 indexed eventId, bytes32 indexed deviceId, string description, uint256 timestamp);

    // Event emitted when a verifier is added or removed
    event VerifierUpdated(address indexed verifier, bool authorized, uint256 timestamp);

    // Modifier to restrict functions to the contract owner
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    // Modifier to restrict functions to authorized verifiers
    modifier onlyVerifier() {
        require(verifiers[msg.sender], "Only authorized verifiers can call this function");
        _;
    }

    // Modifier to check if a device exists
    modifier deviceExists(bytes32 deviceId) {
        require(devices[deviceId].exists, "Device does not exist");
        _;
    }

    // Constructor to set the owner
    constructor() {
        owner = msg.sender;
        verifiers[msg.sender] = true; // Owner is a verifier by default
    }

    // Function to register a new device
    function registerDevice(bytes32 deviceId, bytes32 firmwareHash) external {
        require(!devices[deviceId].exists, "Device ID already exists");

        devices[deviceId] = Device({
            deviceId: deviceId,
            manager: msg.sender,
            firmwareHash: firmwareHash,
            status: VerificationStatus.Pending,
            registeredAt: block.timestamp,
            lastVerifiedAt: 0,
            exists: true
        });

        emit DeviceRegistered(deviceId, msg.sender, firmwareHash, block.timestamp);
    }

    // Function to verify device firmware integrity
    function verifyDevice(bytes32 deviceId, bytes32 firmwareHash) external onlyVerifier deviceExists(deviceId) {
        VerificationStatus status = (devices[deviceId].firmwareHash == firmwareHash) ? VerificationStatus.Passed : VerificationStatus.Failed;

        devices[deviceId].status = status;
        devices[deviceId].lastVerifiedAt = block.timestamp;

        emit DeviceVerified(deviceId, status, firmwareHash, block.timestamp);

        // Log a security event if verification fails
        if (status == VerificationStatus.Failed) {
            bytes32 eventId = keccak256(abi.encodePacked(deviceId, block.timestamp));
            securityEvents[eventId] = SecurityEvent({
                eventId: eventId,
                deviceId: deviceId,
                description: "Firmware verification failed",
                timestamp: block.timestamp
            });
            emit SecurityEventLogged(eventId, deviceId, "Firmware verification failed", block.timestamp);
        }
    }

    // Function to log a security event (e.g., Indicator of Attack)
    function logSecurityEvent(bytes32 deviceId, string calldata description) external onlyVerifier deviceExists(deviceId) {
        bytes32 eventId = keccak256(abi.encodePacked(deviceId, description, block.timestamp));
        securityEvents[eventId] = SecurityEvent({
            eventId: eventId,
            deviceId: deviceId,
            description: description,
            timestamp: block.timestamp
        });

        emit SecurityEventLogged(eventId, deviceId, description, block.timestamp);
    }

    // Function to add or remove a verifier
    function setVerifier(address verifier, bool authorized) external onlyOwner {
        require(verifier != address(0), "Verifier cannot be zero address");
        require(verifiers[verifier] != authorized, "Verifier status already set");

        verifiers[verifier] = authorized;
        emit VerifierUpdated(verifier, authorized, block.timestamp);
    }

    // Function to verify firmware hash
    function checkFirmwareHash(bytes32 deviceId, bytes32 firmwareHash) external view deviceExists(deviceId) returns (bool) {
        return devices[deviceId].firmwareHash == firmwareHash;
    }

    // Function to get device details
    function getDeviceDetails(bytes32 deviceId)
        external
        view
        deviceExists(deviceId)
        returns (
            address manager,
            bytes32 firmwareHash,
            VerificationStatus status,
            uint256 registeredAt,
            uint256 lastVerifiedAt
        )
    {
        require(
            msg.sender == owner ||
            msg.sender == devices[deviceId].manager ||
            verifiers[msg.sender],
            "Not authorized to view device details"
        );

        Device memory device = devices[deviceId];
        return (
            device.manager,
            device.firmwareHash,
            device.status,
            device.registeredAt,
            device.lastVerifiedAt
        );
    }

    // Function to get security event details
    function getSecurityEvent(bytes32 eventId)
        external
        view
        returns (
            bytes32 deviceId,
            string memory description,
            uint256 timestamp
        )
    {
        require(securityEvents[eventId].timestamp != 0, "Security event does not exist");
        require(
            msg.sender == owner ||
            msg.sender == devices[securityEvents[eventId].deviceId].manager ||
            verifiers[msg.sender],
            "Not authorized to view event details"
        );

        SecurityEvent memory secEvent = securityEvents[eventId];
        return (secEvent.deviceId, secEvent.description, secEvent.timestamp);
    }

    // Function to transfer ownership
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "New owner cannot be zero address");
        owner = newOwner;
        verifiers[newOwner] = true; // New owner becomes a verifier
        verifiers[owner] = false; // Remove old owner as verifier
    }
}