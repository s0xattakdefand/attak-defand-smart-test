// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BitwiseSetClearToggle {
    mapping(address => uint8) public flags;

    event FlagToggled(address indexed user, uint8 flagValue);

    /**
     * @notice Toggles a bitwise flag (using XOR).
     * If the flag was set, it clears it; if it was cleared, it sets it.
     * @param user Address whose flags we want to toggle.
     * @param flag The bit flag to toggle (e.g., 0x01, 0x02, etc.).
     */
    function toggleFlag(address user, uint8 flag) public {
        flags[user] ^= flag; // XOR toggles the specific bit
        emit FlagToggled(user, flags[user]);
    }

    /**
     * @notice Check if a specific flag is active for a user.
     */
    function hasFlag(address user, uint8 flag) public view returns (bool) {
        return (flags[user] & flag) == flag;
    }

    /**
     * @notice Read raw flag byte for a user.
     */
    function getRawFlags(address user) public view returns (uint8) {
        return flags[user];
    }
}
