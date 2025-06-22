// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract InterfaceCapabilityRegistry {
    address public admin;

    struct Capability {
        string label;
        bool active;
    }

    // Maps: interfaceId (ERC165 or selector) → Capability
    mapping(bytes4 => Capability) public capabilities;
    mapping(bytes4 => mapping(address => bool)) public accessRoles;

    event CapabilityRegistered(bytes4 indexed id, string label);
    event CapabilityAccessGranted(bytes4 indexed id, address indexed user);
    event CapabilityRevoked(bytes4 indexed id);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerCapability(bytes4 id, string calldata label) external onlyAdmin {
        capabilities[id] = Capability(label, true);
        emit CapabilityRegistered(id, label);
    }

    function revokeCapability(bytes4 id) external onlyAdmin {
        capabilities[id].active = false;
        emit CapabilityRevoked(id);
    }

    function grantAccess(bytes4 id, address user) external onlyAdmin {
        require(capabilities[id].active, "Capability inactive");
        accessRoles[id][user] = true;
        emit CapabilityAccessGranted(id, user);
    }

    function hasCapability(address user, bytes4 id) external view returns (bool) {
        return capabilities[id].active && accessRoles[id][user];
    }

    function enforceCapability(bytes4 id) external view {
        require(capabilities[id].active, "Capability inactive");
        require(accessRoles[id][msg.sender], "Access denied");
    }
}
