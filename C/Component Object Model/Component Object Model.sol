// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @dev Registry that maps interface IDs to implementation contracts
contract ComInterfaceRegistry {
    address public admin;

    struct InterfaceRecord {
        string name;
        address implementation;
        bytes4 interfaceId; // EIP-165 style
        bool active;
    }

    mapping(bytes4 => InterfaceRecord) public interfaces;
    bytes4[] public allInterfaceIds;

    event InterfaceRegistered(bytes4 indexed id, string name, address implementation);
    event InterfaceDeactivated(bytes4 indexed id);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerInterface(
        string calldata name,
        address implementation,
        bytes4 interfaceId
    ) external onlyAdmin {
        require(interfaces[interfaceId].implementation == address(0), "Already exists");

        interfaces[interfaceId] = InterfaceRecord({
            name: name,
            implementation: implementation,
            interfaceId: interfaceId,
            active: true
        });

        allInterfaceIds.push(interfaceId);
        emit InterfaceRegistered(interfaceId, name, implementation);
    }

    function deactivateInterface(bytes4 interfaceId) external onlyAdmin {
        require(interfaces[interfaceId].active, "Already inactive");
        interfaces[interfaceId].active = false;
        emit InterfaceDeactivated(interfaceId);
    }

    function resolve(bytes4 interfaceId) external view returns (address) {
        InterfaceRecord memory rec = interfaces[interfaceId];
        require(rec.active, "Inactive or not found");
        return rec.implementation;
    }

    function listAll() external view returns (bytes4[] memory) {
        return allInterfaceIds;
    }

    function getRecord(bytes4 interfaceId) external view returns (
        string memory,
        address,
        bool
    ) {
        InterfaceRecord memory rec = interfaces[interfaceId];
        return (rec.name, rec.implementation, rec.active);
    }
}
