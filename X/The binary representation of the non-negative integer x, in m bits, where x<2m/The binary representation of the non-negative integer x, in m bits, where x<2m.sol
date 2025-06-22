// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Bit Length Mismatch Attack, Padding Mismatch Attack
/// Defense Types: Strict Bit Length Validation, Normalized Binary Representation

contract BinaryRepresentationChecker {
    event ValidBinary(string binaryString);
    event AttackDetected(string reason);

    /// ATTACK Simulation: bypass m-bit constraint
    function attackOverflowInput(uint256 x, uint256 m) external pure returns (bool) {
        return x >= (1 << m); // true = attack detected
    }

    /// DEFENSE: Proper m-bit binary representation
    function getMbitBinary(uint256 x, uint256 m) external pure returns (string memory) {
        require(m > 0 && m <= 256, "Invalid bit length m (must be between 1 and 256)");
        require(x < (1 << m), "x does not fit into m bits"); // strict check

        bytes memory bits = new bytes(m);
        for (uint256 i = 0; i < m; i++) {
            bits[m - 1 - i] = (x & (1 << i)) != 0 ? bytes1("1") : bytes1("0");
        }
        return string(bits);
    }

    /// DEFENSE: Verify then emit the binary
    function verifyAndEmitBinary(uint256 x, uint256 m) external {
        if (x >= (1 << m)) {
            emit AttackDetected("Bit Length Mismatch Detected");
        } else {
            string memory bin = getMbitBinary(x, m);
            emit ValidBinary(bin);
        }
    }
}
