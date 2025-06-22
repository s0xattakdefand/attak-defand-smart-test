// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract SecureConfigRegistry {
    address public admin;

    struct ConfigEntry {
        string label;
        bytes32 valueHash;
        uint256 updatedAt;
        bool locked;
    }

    mapping(bytes32 => ConfigEntry) public configs;
    bytes32[] public configKeys;

    event ConfigRegistered(bytes32 indexed key, string label, bytes32 valueHash);
    event ConfigUpdated(bytes32 indexed key, bytes32 oldHash, bytes32 newHash);
    event ConfigLocked(bytes32 indexed key);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerConfig(string calldata label, bytes32 valueHash) external onlyAdmin returns (bytes32 key) {
        key = keccak256(abi.encodePacked(label));
        require(configs[key].updatedAt == 0, "Already exists");

        configs[key] = ConfigEntry({
            label: label,
            valueHash: valueHash,
            updatedAt: block.timestamp,
            locked: false
        });

        configKeys.push(key);
        emit ConfigRegistered(key, label, valueHash);
        return key;
    }

    function updateConfig(bytes32 key, bytes32 newHash) external onlyAdmin {
        ConfigEntry storage c = configs[key];
        require(c.updatedAt > 0, "Not found");
        require(!c.locked, "Locked");

        bytes32 oldHash = c.valueHash;
        c.valueHash = newHash;
        c.updatedAt = block.timestamp;

        emit ConfigUpdated(key, oldHash, newHash);
    }

    function lockConfig(bytes32 key) external onlyAdmin {
        require(configs[key].updatedAt > 0, "Not found");
        configs[key].locked = true;
        emit ConfigLocked(key);
    }

    function verifyConfig(bytes32 key, bytes32 expectedHash) external view returns (bool) {
        return configs[key].valueHash == expectedHash;
    }

    function getConfig(bytes32 key) external view returns (string memory, bytes32, uint256, bool) {
        ConfigEntry memory c = configs[key];
        return (c.label, c.valueHash, c.updatedAt, c.locked);
    }

    function getAllKeys() external view returns (bytes32[] memory) {
        return configKeys;
    }
}
