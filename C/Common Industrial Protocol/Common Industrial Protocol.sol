// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CIPRelayRegistry {
    address public admin;

    struct Device {
        string name;
        bool active;
        uint256 lastSeen;
    }

    mapping(address => Device) public devices;
    mapping(bytes32 => bool) public usedPayloads;

    event DeviceRegistered(address indexed device, string name);
    event DeviceStatusUpdated(address indexed device, bool active);
    event CIPDataRelayed(
        address indexed device,
        string messageType,
        uint256 value,
        string unit,
        bytes32 payloadHash,
        uint256 timestamp
    );

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier onlyDevice() {
        require(devices[msg.sender].active, "Device not authorized");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerDevice(address deviceAddr, string calldata name) external onlyAdmin {
        devices[deviceAddr] = Device(name, true, 0);
        emit DeviceRegistered(deviceAddr, name);
    }

    function updateDeviceStatus(address deviceAddr, bool active) external onlyAdmin {
        require(bytes(devices[deviceAddr].name).length > 0, "Device not found");
        devices[deviceAddr].active = active;
        emit DeviceStatusUpdated(deviceAddr, active);
    }

    function relayCIPData(
        string calldata messageType,
        uint256 value,
        string calldata unit,
        uint256 timestamp
    ) external onlyDevice {
        bytes32 payloadHash = keccak256(abi.encodePacked(msg.sender, messageType, value, unit, timestamp));
        require(!usedPayloads[payloadHash], "Replay detected");

        usedPayloads[payloadHash] = true;
        devices[msg.sender].lastSeen = block.timestamp;

        emit CIPDataRelayed(msg.sender, messageType, value, unit, payloadHash, block.timestamp);
    }

    function getDevice(address device) external view returns (string memory name, bool active, uint256 lastSeen) {
        Device memory d = devices[device];
        return (d.name, d.active, d.lastSeen);
    }
}
