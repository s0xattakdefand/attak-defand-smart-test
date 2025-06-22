// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Zero Injection Attack, Null Payload Attack, Sparse Key Attack
/// Defense Types: Explicit Non-Zero Validation, Zero-Only Validation

contract ZeroBitStringHandler {
    event ZeroStringGenerated(bytes zeroString);
    event AttackDetected(string reason);

    /// ATTACK Simulation: Bypass checks with all zero bit string
    function attackZeroInjection(bytes memory input) external pure returns (bool) {
        for (uint256 i = 0; i < input.length; i++) {
            if (input[i] != 0x00) {
                return false; // not all zero
            }
        }
        return true; // attack successful if all zero
    }

    /// DEFENSE: Generate exactly x zero bits (in bytes)
    function generateZeroString(uint256 xBits) external pure returns (bytes memory) {
        require(xBits > 0 && xBits <= 2048, "Invalid xBits range"); // reasonable bounds
        uint256 bytesNeeded = (xBits + 7) / 8; // Round up to full bytes

        bytes memory zeroString = new bytes(bytesNeeded);
        return zeroString;
    }

    /// DEFENSE: Validate that input is exactly all zeros and matches expected x bits
    function validateZeroString(bytes memory input, uint256 expectedBits) external {
        uint256 expectedBytes = (expectedBits + 7) / 8;
        require(input.length == expectedBytes, "Incorrect byte length");

        for (uint256 i = 0; i < input.length; i++) {
            if (input[i] != 0x00) {
                emit AttackDetected("Non-zero bit detected");
                revert("Bit string is not all zeros");
            }
        }

        emit ZeroStringGenerated(input);
    }

    /// Utility: Quick check if any nonzero byte exists
    function isAllZero(bytes memory input) external pure returns (bool) {
        for (uint256 i = 0; i < input.length; i++) {
            if (input[i] != 0x00) {
                return false;
            }
        }
        return true;
    }
}
