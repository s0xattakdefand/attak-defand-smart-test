// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Device Spoofing Attack, Unauthorized Instrument Operation, Data Integrity Attack
/// Defense Types: Secure Device Registration, Role-based Operation Control, Signed Data Logging

contract MedicalInstrumentationManager {
    address public regulator;

    struct Device {
        bool registered;
        address owner;
        string metadata;
    }

    mapping(bytes32 => Device) public devices; // deviceId => Device
    mapping(address => bool) public authorizedOperators; // doctors, nurses, technicians

    event DeviceRegistered(bytes32 indexed deviceId, address indexed owner, string metadata);
    event DeviceOperated(bytes32 indexed deviceId, address indexed operator, string operation);
    event DataLogged(bytes32 indexed deviceId, address indexed operator, string dataHash);

    constructor() {
        regulator = msg.sender;
    }

    modifier onlyRegulator() {
        require(msg.sender == regulator, "Only regulator");
        _;
    }

    modifier onlyOperator() {
        require(authorizedOperators[msg.sender], "Unauthorized operator");
        _;
    }

    /// ATTACK Simulation: Device spoofing without registration
    function attackFakeDeviceOperation(bytes32 fakeDeviceId, string calldata fakeOperation) external {
        emit DeviceOperated(fakeDeviceId, msg.sender, fakeOperation);
    }

    /// DEFENSE: Register real medical devices securely
    function registerDevice(bytes32 deviceId, address owner, string calldata metadata) external onlyRegulator {
        require(!devices[deviceId].registered, "Device already registered");

        devices[deviceId] = Device({
            registered: true,
            owner: owner,
            metadata: metadata
        });

        emit DeviceRegistered(deviceId, owner, metadata);
    }

    /// DEFENSE: Authorize medical personnel securely
    function authorizeOperator(address operator) external onlyRegulator {
        authorizedOperators[operator] = true;
    }

    /// DEFENSE: Operate device only if registered and by authorized operator
    function operateDevice(bytes32 deviceId, string calldata operation) external onlyOperator {
        require(devices[deviceId].registered, "Device not registered");

        emit DeviceOperated(deviceId, msg.sender, operation);
    }

    /// DEFENSE: Log device data output securely
    function logDeviceData(bytes32 deviceId, string calldata dataHash) external onlyOperator {
        require(devices[deviceId].registered, "Device not registered");

        emit DataLogged(deviceId, msg.sender, dataHash);
    }

    /// View device details
    function viewDevice(bytes32 deviceId) external view returns (bool registered, address owner, string memory metadata) {
        Device memory d = devices[deviceId];
        return (d.registered, d.owner, d.metadata);
    }
}
