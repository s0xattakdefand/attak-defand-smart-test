// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Duplicate Insertion Attack, Overwrite/Drift Attack
/// Defense Types: Set Membership Validation, Strict Insertion Rules

contract IntegerSetManager {
    event SetCreated(uint256[] set);
    event DuplicateInsertionDetected(uint256 duplicateValue);

    mapping(address => mapping(uint256 => bool)) public userSetMembership;
    mapping(address => uint256[]) public userSets;

    /// ATTACK Simulation: Try to insert duplicates manually
    function attackDuplicateInsert(uint256 x, uint256 y) external {
        userSets[msg.sender].push(x);
        userSets[msg.sender].push(y);
        // No membership check here — this simulates an attack!
    }

    /// DEFENSE: Strict insertion ensuring set properties
    function createSet(uint256 x, uint256 y) external {
        require(x != y, "Duplicate values not allowed in set");

        _clearPreviousSet(msg.sender); // optional: clear any old set

        userSets[msg.sender].push(x);
        userSets[msg.sender].push(y);

        userSetMembership[msg.sender][x] = true;
        userSetMembership[msg.sender][y] = true;

        emit SetCreated(userSets[msg.sender]);
    }

    /// DEFENSE: Insert additional element into the set
    function insertToSet(uint256 value) external {
        require(!userSetMembership[msg.sender][value], "Duplicate insertion detected");

        userSets[msg.sender].push(value);
        userSetMembership[msg.sender][value] = true;
    }

    /// Clear a user's previous set (optional utility)
    function _clearPreviousSet(address user) internal {
        uint256 length = userSets[user].length;
        for (uint256 i = 0; i < length; i++) {
            uint256 val = userSets[user][i];
            userSetMembership[user][val] = false;
        }
        delete userSets[user];
    }

    /// View the current set
    function viewSet(address user) external view returns (uint256[] memory) {
        return userSets[user];
    }
}
