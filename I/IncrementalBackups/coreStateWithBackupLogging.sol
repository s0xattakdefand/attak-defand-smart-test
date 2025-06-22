// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract IncrementalBackupRegistry {
    struct StateBackup {
        address editor;
        uint256 version;
        string key;
        string value;
        uint256 timestamp;
    }

    uint256 public latestVersion;
    mapping(uint256 => StateBackup) public backups;
    mapping(string => string) public currentState;

    event StateUpdated(string key, string newValue, uint256 version);

    function updateState(string calldata key, string calldata newValue) external {
        latestVersion++;

        // Log only changes, not full state
        backups[latestVersion] = StateBackup({
            editor: msg.sender,
            version: latestVersion,
            key: key,
            value: newValue,
            timestamp: block.timestamp
        });

        currentState[key] = newValue;
        emit StateUpdated(key, newValue, latestVersion);
    }

    function getBackup(uint256 version) external view returns (StateBackup memory) {
        return backups[version];
    }
}
