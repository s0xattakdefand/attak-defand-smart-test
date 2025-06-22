// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract AddressMetadata {
    struct DeviceInfo {
        string hostname;
        string role;
        uint256 lastSeen;
    }

    mapping(address => DeviceInfo) public devices;

    function updateDevice(string memory hostname, string memory role) external {
        devices[msg.sender] = DeviceInfo(hostname, role, block.timestamp);
    }

    function getDevice(address addr) external view returns (DeviceInfo memory) {
        return devices[addr];
    }
}
