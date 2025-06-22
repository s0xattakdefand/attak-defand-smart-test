// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Bit Length Mismatch Attack, Short Input Attack, Truncation Attack
/// Defense Types: Strict Bit Length Verification, Dynamic Length Checking

contract BitStringLengthValidator {
    event BitLengthValid(uint256 bitLength);
    event AttackDetected(string reason);

    /// ATTACK Simulation: submit wrong-length bit string
    function attackShortBitString(bytes memory x) external pure returns (uint256) {
        uint256 bitLength = x.length * 8;
        return bitLength; // attacker tries to slip short input
    }

    /// DEFENSE: Validate bit string length matches expected
    function validateBitStringLength(bytes memory x, uint256 expectedBits) external {
        uint256 bitLength = x.length * 8;

        if (bitLength != expectedBits) {
            emit AttackDetected("Bit Length Mismatch Detected");
            revert("Invalid bit length");
        }

        emit BitLengthValid(bitLength);
    }

    /// DEFENSE: Flexible minimum bit length enforcement
    function validateMinimumBitLength(bytes memory x, uint256 minimumBits) external {
        uint256 bitLength = x.length * 8;

        if (bitLength < minimumBits) {
            emit AttackDetected("Bit String Too Short");
            revert("Bit length too short");
        }

        emit BitLengthValid(bitLength);
    }

    /// View bit length directly
    function getBitLength(bytes memory x) external pure returns (uint256) {
        return x.length * 8;
    }
}
