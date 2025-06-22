// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ControlItemRegistry — Track and enforce modular security and governance control items
contract ControlItemRegistry {
    address public owner;

    struct ControlItem {
        string label;
        bool enabled;
    }

    mapping(bytes32 => ControlItem) public controls;

    event ControlItemRegistered(bytes32 indexed id, string label);
    event ControlItemUpdated(bytes32 indexed id, bool enabled);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    modifier requireControl(string memory label) {
        bytes32 id = keccak256(abi.encodePacked(label));
        require(controls[id].enabled, string(abi.encodePacked("Control disabled: ", label)));
        _;
    }

    constructor() {
        owner = msg.sender;

        // Example default items
        registerControlItem("UPGRADE_AUTH", true);
        registerControlItem("WITHDRAW_FUNDS", true);
        registerControlItem("PAUSE_SYSTEM", true);
    }

    function registerControlItem(string memory label, bool enabled) public onlyOwner {
        bytes32 id = keccak256(abi.encodePacked(label));
        controls[id] = ControlItem(label, enabled);
        emit ControlItemRegistered(id, label);
    }

    function setControlItemStatus(string memory label, bool enabled) external onlyOwner {
        bytes32 id = keccak256(abi.encodePacked(label));
        controls[id].enabled = enabled;
        emit ControlItemUpdated(id, enabled);
    }

    // ✅ Example function using control item enforcement
    function performSensitiveAction() external requireControl("WITHDRAW_FUNDS") returns (string memory) {
        return "Funds withdrawn with control item enabled.";
    }
}
