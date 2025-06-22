// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * An interface for the DR (Disaster Recovery) contract,
 * so primary can call syncBackup(...) on it.
 */
interface IDR {
    function syncBackup(address user, uint256 newBalance) external;
}

/**
 * @title DRBackup
 * A 'warm' DR site that partially syncs user balances from the primary contract.
 */
contract DRBackup is IDR {
    // Mirror state
    mapping(address => uint256) public mirroredBalances;
    address public primary;

    constructor(address _primary) {
        primary = _primary;
    }

    /**
     * @dev Syncs the updated balance from primary contract
     * Must be called only by the primary.
     */
    function syncBackup(address user, uint256 newBalance) external override {
        require(msg.sender == primary, "Not primary");
        mirroredBalances[user] = newBalance;
    }
}
