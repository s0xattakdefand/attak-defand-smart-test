// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Modulo Bias Attack, Wraparound Attack, Division-by-Zero Attack
/// Defense Types: Modulo Validation, Range Check, Entropy Normalization

contract ModuloOperationHandler {
    event ModuloResult(uint256 result);
    event AttackDetected(string reason);

    /// ATTACK Simulation: Unsafe modulus operation
    function attackUnsafeMod(uint256 a, uint256 b) external pure returns (uint256) {
        // dangerous: no check for b==0
        return a % b;
    }

    /// DEFENSE: Safe modulus operation with validation
    function safeMod(uint256 a, uint256 b) external returns (uint256) {
        if (b == 0) {
            emit AttackDetected("Division by zero detected");
            revert("Cannot mod by zero");
        }

        uint256 result = a % b;
        emit ModuloResult(result);
        return result;
    }

    /// DEFENSE: Range-checked safe modulus
    function safeModWithRange(uint256 a, uint256 b, uint256 maxA, uint256 minB) external returns (uint256) {
        require(a <= maxA, "Input a too large");
        require(b >= minB, "Input b too small");
        require(b != 0, "Cannot mod by zero");

        uint256 result = a % b;
        emit ModuloResult(result);
        return result;
    }
}
