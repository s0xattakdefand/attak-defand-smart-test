// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ConfigurationItemRegistry {
    address public admin;

    struct CI {
        string key;
        bytes32 value;
        bool immutableFlag;
    }

    mapping(string => CI) public configItems;
    string[] public registeredKeys;

    event CIRegistered(string key, bytes32 value);
    event CIUpdated(string key, bytes32 oldValue, bytes32 newValue);
    event CILocked(string key);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerCI(string calldata key, bytes32 value) external onlyAdmin {
        require(configItems[key].value == 0, "CI already registered");
        configItems[key] = CI(key, value, false);
        registeredKeys.push(key);
        emit CIRegistered(key, value);
    }

    function updateCI(string calldata key, bytes32 newValue) external onlyAdmin {
        CI storage ci = configItems[key];
        require(!ci.immutableFlag, "CI is immutable");
        bytes32 old = ci.value;
        ci.value = newValue;
        emit CIUpdated(key, old, newValue);
    }

    function lockCI(string calldata key) external onlyAdmin {
        configItems[key].immutableFlag = true;
        emit CILocked(key);
    }

    function getCI(string calldata key) external view returns (bytes32, bool) {
        CI storage ci = configItems[key];
        return (ci.value, ci.immutableFlag);
    }

    function getAllKeys() external view returns (string[] memory) {
        return registeredKeys;
    }
}
