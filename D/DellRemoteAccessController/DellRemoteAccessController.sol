// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// RemoteAccessController contract for managing virtual devices with secure access
contract RemoteAccessController {
    // Contract owner (e.g., system administrator)
    address public owner;

    // Enum to represent device status
    enum DeviceStatus { Offline, Online, Maintenance, Failed }

    // Structure to store device metadata
    struct Device {
        bytes32 deviceId; // Unique identifier for the device
        address manager; // Address of the device manager (creator)
        DeviceStatus status; // Current status of the device
        uint256 createdAt; // Timestamp when device was created
        uint256 updatedAt; // Timestamp of last status update
        bytes32 telemetryHash; // Hash of telemetry data (e.g., performance metrics)
        bool exists; // Flag to check if device exists
    }

    // Mapping to store devices by device ID
    mapping(bytes32 => Device) public devices;

    // Mapping to store authorized operators for each device
    mapping(bytes32 => mapping(address => bool)) public operators;

    // Event emitted when a device is created
    event DeviceCreated(bytes32 indexed deviceId, address indexed manager, uint256 timestamp);

    // Event emitted when a device status is updated
    event StatusUpdated(bytes32 indexed deviceId, DeviceStatus status, uint256 timestamp);

    // Event emitted when telemetry data is updated
    event TelemetryUpdated(bytes32 indexed deviceId, bytes32 telemetryHash, uint256 timestamp);

    // Event emitted when an operator is added or removed
    event OperatorUpdated(bytes32 indexed deviceId, address indexed operator, bool authorized, uint256 timestamp);

    // Modifier to restrict functions to the contract owner
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    // Modifier to restrict functions to authorized operators or owner
    modifier onlyAuthorized(bytes32 deviceId) {
        require(
            msg.sender == owner || operators[deviceId][msg.sender],
            "Not authorized to perform this action"
        );
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
        operators[bytes32(0)][msg.sender] = true; // Owner is an operator for all devices
    }

    // Function to create a new device
    function createDevice(bytes32 deviceId, bytes32 initialTelemetryHash) external {
        require(!devices[deviceId].exists, "Device ID already exists");

        devices[deviceId] = Device({
            deviceId: deviceId,
            manager: msg.sender,
            status: DeviceStatus.Offline,
            createdAt: block.timestamp,
            updatedAt: block.timestamp,
            telemetryHash: initialTelemetryHash,
            exists: true
        });

        // Grant operator access to the creator
        operators[deviceId][msg.sender] = true;

        emit DeviceCreated(deviceId, msg.sender, block.timestamp);
        emit TelemetryUpdated(deviceId, initialTelemetryHash, block.timestamp);
    }

    // Function to update device status
    function updateStatus(bytes32 deviceId, DeviceStatus status) external onlyAuthorized(deviceId) deviceExists(deviceId) {
        require(status != devices[deviceId].status, "Status must be different");
        require(uint(status) <= uint(DeviceStatus.Failed), "Invalid status");

        devices[deviceId].status = status;
        devices[deviceId].updatedAt = block.timestamp;

        emit StatusUpdated(deviceId, status, block.timestamp);
    }

    // Function to update telemetry data
    function updateTelemetry(bytes32 deviceId, bytes32 telemetryHash) external onlyAuthorized(deviceId) deviceExists(deviceId) {
        devices[deviceId].telemetryHash = telemetryHash;
        devices[deviceId].updatedAt = block.timestamp;

        emit TelemetryUpdated(deviceId, telemetryHash, block.timestamp);
    }

    // Function to add or remove an operator for a device
    function setOperator(bytes32 deviceId, address operator, bool authorized) external onlyOwner deviceExists(deviceId) {
        require(operator != address(0), "Operator cannot be zero address");
        require(operators[deviceId][operator] != authorized, "Operator status already set");

        operators[deviceId][operator] = authorized;
        emit OperatorUpdated(deviceId, operator, authorized, block.timestamp);
    }

    // Function to verify telemetry hash
    function verifyTelemetry(bytes32 deviceId, bytes32 telemetryHash) external view deviceExists(deviceId) returns (bool) {
        return devices[deviceId].telemetryHash == telemetryHash;
    }

    // Function to get device details
    function getDeviceDetails(bytes32 deviceId)
        external
        view
        deviceExists(deviceId)
        returns (
            address manager,
            DeviceStatus status,
            uint256 createdAt,
            uint256 updatedAt,
            bytes32 telemetryHash
        )
    {
        require(
            msg.sender == owner ||
            msg.sender == devices[deviceId].manager ||
            operators[deviceId][msg.sender],
            "Not authorized to view device details"
        );

        Device memory device = devices[deviceId];
        return (
            device.manager,
            device.status,
            device.createdAt,
            device.updatedAt,
            device.telemetryHash
        );
    }

    // Function to transfer ownership
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "New owner cannot be zero address");
        owner = newOwner;
        operators[bytes32(0)][newOwner] = true; // New owner is an operator for all devices
        operators[bytes32(0)][owner] = false; // Remove old owner as global operator
    }
}