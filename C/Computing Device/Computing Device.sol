// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract DeviceAccessRegistry {
    address public admin;

    struct Device {
        string deviceType;
        address deviceAddress;
        bool active;
        uint256 registeredAt;
    }

    mapping(address => Device) public devices;
    address[] public deviceList;

    event DeviceRegistered(address indexed device, string deviceType);
    event DeviceRevoked(address indexed device);
    event DeviceUsed(address indexed device, string purpose);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier onlyActiveDevice() {
        require(devices[msg.sender].active, "Device inactive");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerDevice(address device, string calldata deviceType) external onlyAdmin {
        devices[device] = Device({
            deviceType: deviceType,
            deviceAddress: device,
            active: true,
            registeredAt: block.timestamp
        });
        deviceList.push(device);
        emit DeviceRegistered(device, deviceType);
    }

    function revokeDevice(address device) external onlyAdmin {
        devices[device].active = false;
        emit DeviceRevoked(device);
    }

    function logDeviceUsage(string calldata purpose) external onlyActiveDevice {
        emit DeviceUsed(msg.sender, purpose);
    }

    function isTrusted(address device) external view returns (bool) {
        return devices[device].active;
    }

    function getDevice(address device) external view returns (Device memory) {
        return devices[device];
    }

    function getAllDevices() external view returns (address[] memory) {
        return deviceList;
    }
}
