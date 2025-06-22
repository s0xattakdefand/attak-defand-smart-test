// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract ConfigurationSettingsManager is AccessControl {
    bytes32 public constant CONFIG_ADMIN = keccak256("CONFIG_ADMIN");
    bool public configLocked;

    mapping(string => bytes32) public settings;
    mapping(string => bytes32) public baselineHash;

    event ConfigChanged(string key, bytes32 oldValue, bytes32 newValue);
    event ConfigBaselineSet(string key, bytes32 hash);
    event ConfigLocked();

    modifier onlyAdmin() {
        require(hasRole(CONFIG_ADMIN, msg.sender), "Not authorized");
        _;
    }

    modifier notLocked() {
        require(!configLocked, "Settings are locked");
        _;
    }

    constructor() {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setupRole(CONFIG_ADMIN, msg.sender);
    }

    function setSetting(string calldata key, bytes32 value) external onlyAdmin notLocked {
        bytes32 old = settings[key];
        settings[key] = value;
        emit ConfigChanged(key, old, value);
    }

    function setBaseline(string calldata key, bytes32 hash) external onlyAdmin {
        baselineHash[key] = hash;
        emit ConfigBaselineSet(key, hash);
    }

    function checkBaseline(string calldata key) external view returns (bool) {
        return keccak256(abi.encode(settings[key])) == baselineHash[key];
    }

    function lockSettings() external onlyRole(DEFAULT_ADMIN_ROLE) {
        configLocked = true;
        emit ConfigLocked();
    }

    function getSetting(string calldata key) external view returns (bytes32) {
        return settings[key];
    }
}
