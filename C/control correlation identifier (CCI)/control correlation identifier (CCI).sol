// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title CCIMappedControl — Demonstrates linking smart contract controls to NIST/ISO control IDs via CCI
contract CCIMappedControl {
    address public owner;
    mapping(bytes32 => string) public controlDescriptions;
    mapping(bytes32 => string) public cciTags;

    event ControlExecuted(bytes32 indexed controlId, string cciRef, address indexed by, string context);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;

        // Example CCI registrations
        _registerControl("RBAC_ADMIN_ASSIGN", "CCI-000015", "Restrict assignment of roles to authorized identities");
        _registerControl("EMERGENCY_PAUSE", "CCI-000060", "Implement emergency system shutdown mechanism");
    }

    function _registerControl(string memory controlKey, string memory cciRef, string memory description) internal {
        bytes32 controlId = keccak256(abi.encodePacked(controlKey));
        cciTags[controlId] = cciRef;
        controlDescriptions[controlId] = description;
    }

    /// 🔐 CCI: CCI-000015 (RBAC)
    function assignOwnership(address newOwner) external onlyOwner {
        owner = newOwner;
        emit ControlExecuted(
            keccak256("RBAC_ADMIN_ASSIGN"),
            cciTags[keccak256("RBAC_ADMIN_ASSIGN")],
            msg.sender,
            "Ownership transferred"
        );
    }

    /// 🔐 CCI: CCI-000060 (Emergency Stop)
    bool public paused;

    function emergencyPause() external onlyOwner {
        paused = true;
        emit ControlExecuted(
            keccak256("EMERGENCY_PAUSE"),
            cciTags[keccak256("EMERGENCY_PAUSE")],
            msg.sender,
            "System paused"
        );
    }

    function getControlDetails(string calldata key) external view returns (string memory cci, string memory desc) {
        bytes32 id = keccak256(abi.encodePacked(key));
        return (cciTags[id], controlDescriptions[id]);
    }
}
