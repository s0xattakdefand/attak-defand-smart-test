// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Prefix Forgery Attack, Mixed Encoding Attack, Null-Prefix Drift Attack
/// Defense Types: Strict Prefix Validation, Hexadecimal Length Check, Encoding Normalization

contract HexPrefixValidator {
    event HexPrefixValid(string input);
    event AttackDetected(string reason);

    /// ATTACK Simulation: Input without "0x" prefix
    function attackNoPrefix(string memory input) external pure returns (bool) {
        bytes memory inputBytes = bytes(input);
        if (inputBytes.length < 2) {
            return true; // Too short — likely no prefix
        }
        return !(inputBytes[0] == "0" && (inputBytes[1] == "x" || inputBytes[1] == "X"));
    }

    /// DEFENSE: Validate hex string has "0x" prefix and proper even hex length
    function validateHexPrefix(string memory input) external {
        bytes memory inputBytes = bytes(input);

        require(inputBytes.length >= 2, "Input too short");
        require(inputBytes[0] == "0" && (inputBytes[1] == "x" || inputBytes[1] == "X"), "Missing 0x prefix");

        uint256 hexCharLength = inputBytes.length - 2;
        require(hexCharLength % 2 == 0, "Hex data must have even number of characters");

        emit HexPrefixValid(input);
    }

    /// DEFENSE: Extract raw bytes from hex string (after prefix)
    function extractRawBytes(string memory input) external pure returns (bytes memory) {
        bytes memory inputBytes = bytes(input);
        require(inputBytes.length >= 2, "Input too short");
        require(inputBytes[0] == "0" && (inputBytes[1] == "x" || inputBytes[1] == "X"), "Missing 0x prefix");

        uint256 rawLength = inputBytes.length - 2;
        require(rawLength % 2 == 0, "Invalid hex length");

        bytes memory raw = new bytes(rawLength / 2);
        for (uint256 i = 0; i < raw.length; i++) {
            raw[i] = bytes1(
                (fromHexChar(uint8(inputBytes[2 + 2 * i])) << 4) |
                fromHexChar(uint8(inputBytes[3 + 2 * i]))
            );
        }
        return raw;
    }

    // Helper: Convert hex character to byte
    function fromHexChar(uint8 c) internal pure returns (uint8) {
        if (bytes1(c) >= "0" && bytes1(c) <= "9") {
            return c - uint8(bytes1("0"));
        }
        if (bytes1(c) >= "a" && bytes1(c) <= "f") {
            return 10 + c - uint8(bytes1("a"));
        }
        if (bytes1(c) >= "A" && bytes1(c) <= "F") {
            return 10 + c - uint8(bytes1("A"));
        }
        revert("Invalid hex character");
    }
}
