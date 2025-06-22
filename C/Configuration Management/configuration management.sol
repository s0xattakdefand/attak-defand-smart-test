// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract ConfigurationControlManager is AccessControl {
    bytes32 public constant CONFIG_SETTER = keccak256("CONFIG_SETTER");

    struct PendingChange {
        string key;
        bytes32 value;
        uint256 unlockBlock;
    }

    mapping(string => bytes32) public config;
    mapping(string => PendingChange) public pending;
    uint256 public constant delayBlocks = 10;

    event ConfigChangeRequested(string key, bytes32 newValue, uint256 unlockBlock);
    event ConfigChanged(string key, bytes32 oldValue, bytes32 newValue);

    constructor() {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setupRole(CONFIG_SETTER, msg.sender);
    }

    function requestChange(string calldata key, bytes32 newValue) external onlyRole(CONFIG_SETTER) {
        uint256 unlockBlock = block.number + delayBlocks;
        pending[key] = PendingChange(key, newValue, unlockBlock);
        emit ConfigChangeRequested(key, newValue, unlockBlock);
    }

    function applyChange(string calldata key) external {
        PendingChange memory change = pending[key];
        require(change.unlockBlock > 0 && block.number >= change.unlockBlock, "Not yet unlocked");

        bytes32 oldVal = config[key];
        config[key] = change.value;
        delete pending[key];

        emit ConfigChanged(key, oldVal, change.value);
    }

    function getConfig(string calldata key) external view returns (bytes32) {
        return config[key];
    }
}
