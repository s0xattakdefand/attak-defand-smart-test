// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * DBM CONVERSION DEMO – FIXED
 * “Decibels referenced to one milliwatt” (dBm)
 */

contract DbmConverter {
    /// @notice Compute ⌊log₁₀(x)⌋ for x > 0
    function floorLog10(uint256 x) public pure returns (uint8) {
        require(x > 0, "x must be > 0");
        uint8 result = 0;
        while (x >= 10) {
            x /= 10;
            result++;
        }
        return result;
    }

    /// @notice Convert power in milliwatts to approximate dBm:
    ///         dBm = 10 × ⌊log₁₀(power_mW)⌋
    function toDbm(uint256 power_mW) external pure returns (int256) {
        require(power_mW > 0, "power must be > 0");
        uint8 lg = floorLog10(power_mW);
        // avoid direct uint8→int256 conversion by going through uint256
        uint256 dbmUnsigned = uint256(lg) * 10;
        return int256(dbmUnsigned);
    }

    /// @notice Convert dBm back to milliwatts:
    ///         power_mW = 10^(dBm/10), supports non‐negative multiples of 10 only
    function toMilliwatt(int256 dbm) external pure returns (uint256) {
        require(dbm >= 0, "dBm must be non-negative");
        require(dbm % 10 == 0,      "dBm must be a multiple of 10");
        uint256 exp = uint256(dbm / 10);
        return 10 ** exp;
    }
}
