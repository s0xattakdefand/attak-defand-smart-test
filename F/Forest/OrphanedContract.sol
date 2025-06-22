// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Orphaned contracts deployed without access control or root context.
 * Each contract is isolated — no forest protection.
 */
contract OrphanedContract {
    string public config;
    address public owner;

    constructor(string memory _config) {
        config = _config;
        owner = msg.sender;
    }

    function updateConfig(string memory _newConfig) external {
        require(msg.sender == owner, "Not owner");
        config = _newConfig;
    }
}
