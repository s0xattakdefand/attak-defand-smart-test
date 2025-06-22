// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CCEConfigRegistry {
    address public admin;

    struct ConfigEntry {
        string label;            // e.g., "CCE-12345: upgrade delay"
        bytes32 valueHash;       // keccak256 of config value
        uint256 updatedAt;
    }

    mapping(bytes32 => ConfigEntry) public configs;
    bytes32[] public configKeys;

    event ConfigRegistered(bytes32 indexed key, string label, bytes32 valueHash);
    event ConfigUpdated(bytes32 indexed key, bytes32 oldHash, bytes32 newHash);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerConfig(string calldata label, bytes32 valueHash) external onlyAdmin returns (bytes32 key) {
        key = keccak256(abi.encodePacked(label));
        require(configs[key].updatedAt == 0, "Config already exists");

        configs[key] = ConfigEntry({
            label: label,
            valueHash: valueHash,
            updatedAt: block.timestamp
        });

        configKeys.push(key);
        emit ConfigRegistered(key, label, valueHash);
    }

    function updateConfig(bytes32 key, bytes32 newHash) external onlyAdmin {
        require(configs[key].updatedAt > 0, "Config not registered");

        bytes32 oldHash = configs[key].valueHash;
        configs[key].valueHash = newHash;
        configs[key].updatedAt = block.timestamp;

        emit ConfigUpdated(key, oldHash, newHash);
    }

    function verifyConfig(bytes32 key, bytes32 expectedHash) external view returns (bool matchStatus) {
        return configs[key].valueHash == expectedHash;
    }

    function getAllConfigKeys() external view returns (bytes32[] memory) {
        return configKeys;
    }

    function getConfig(bytes32 key) external view returns (string memory, bytes32, uint256) {
        ConfigEntry memory c = configs[key];
        return (c.label, c.valueHash, c.updatedAt);
    }
}
