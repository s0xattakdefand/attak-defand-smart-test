// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BitmaskFiltering {
    uint8 public mask = 0x03;  // 00000011
    uint8 public flags = 0x07; // 00000111

    /**
     * @notice Check if the `mask` is fully present in `flags`.
     * Equivalent to: all bits in `mask` are set in `flags`.
     */
    function isMaskMatched() public view returns (bool) {
        bool isMatch = (flags & mask) == mask; // ✅ valid name
        return isMatch;
    }

    /**
     * @notice Update mask value (for demonstration).
     */
    function updateMask(uint8 newMask) public {
        mask = newMask;
    }

    /**
     * @notice Update flags value (for demonstration).
     */
    function updateFlags(uint8 newFlags) public {
        flags = newFlags;
    }
}
