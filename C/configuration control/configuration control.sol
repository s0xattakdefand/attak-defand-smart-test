// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract ConfigurationControlCenter is AccessControl {
    bytes32 public constant CONFIG_ADMIN = keccak256("CONFIG_ADMIN");
    uint256 public constant DELAY_BLOCKS = 20;

    struct Config {
        bytes32 value;
        uint256 unlockBlock;
        bool active;
    }

    mapping(string => Config) public configByKey;
    mapping(string => bytes32) public baseline;

    event ConfigChangeRequested(string key, bytes32 newValue, uint256 unlockBlock);
    event ConfigChangeApplied(string key, bytes32 newValue);
    event ConfigBaselineSet(string key, bytes32 baselineHash);

    constructor() {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setupRole(CONFIG_ADMIN, msg.sender);
    }

    function requestConfigChange(string calldata key, bytes32 newValue) external onlyRole(CONFIG_ADMIN) {
        configByKey[key] = Config({
            value: newValue,
            unlockBlock: block.number + DELAY_BLOCKS,
            active: false
        });
        emit ConfigChangeRequested(key, newValue, block.number + DELAY_BLOCKS);
    }

    function applyConfigChange(string calldata key) external onlyRole(CONFIG_ADMIN) {
        Config storage cfg = configByKey[key];
        require(!cfg.active, "Already active");
        require(block.number >= cfg.unlockBlock, "Delay not passed");

        cfg.active = true;
        emit ConfigChangeApplied(key, cfg.value);
    }

    function getConfig(string calldata key) external view returns (bytes32 value, bool active) {
        Config storage cfg = configByKey[key];
        return (cfg.value, cfg.active);
    }

    function setBaseline(string calldata key, bytes32 hash) external onlyRole(CONFIG_ADMIN) {
        baseline[key] = hash;
        emit ConfigBaselineSet(key, hash);
    }

    function checkBaseline(string calldata key) external view returns (bool matches) {
        return keccak256(abi.encode(configByKey[key].value)) == baseline[key];
    }
}
