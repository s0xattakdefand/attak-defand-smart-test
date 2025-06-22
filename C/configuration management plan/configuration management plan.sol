// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ConfigurationManagementPlan {
    address public admin;
    uint256 public constant delayBlocks = 20;

    struct ConfigItem {
        bytes32 value;
        bytes32 baselineHash;
        uint256 unlockBlock;
        bool approved;
    }

    mapping(string => ConfigItem) public configItems;
    string[] public registeredKeys;

    event ConfigProposed(string key, bytes32 value, uint256 unlockBlock);
    event ConfigApproved(string key, bytes32 newValue);
    event ConfigBaselineSet(string key, bytes32 hash);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function proposeConfigChange(string calldata key, bytes32 newValue) external onlyAdmin {
        configItems[key] = ConfigItem({
            value: newValue,
            baselineHash: configItems[key].baselineHash,
            unlockBlock: block.number + delayBlocks,
            approved: false
        });
        emit ConfigProposed(key, newValue, block.number + delayBlocks);
    }

    function approveConfigChange(string calldata key) external onlyAdmin {
        ConfigItem storage ci = configItems[key];
        require(block.number >= ci.unlockBlock, "Not yet unlocked");
        ci.approved = true;
        emit ConfigApproved(key, ci.value);
    }

    function setBaselineHash(string calldata key, bytes32 hash) external onlyAdmin {
        configItems[key].baselineHash = hash;
        emit ConfigBaselineSet(key, hash);
    }

    function verifyBaseline(string calldata key) external view returns (bool matches) {
        return keccak256(abi.encode(configItems[key].value)) == configItems[key].baselineHash;
    }

    function getConfig(string calldata key) external view returns (ConfigItem memory) {
        return configItems[key];
    }
}
