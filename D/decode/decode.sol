// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title DataDecoder
 * @notice Converts encoded data back to its original form of representation.
 * @dev Implements hexadecimal‐string decoding (per IETF RFC 4949 “decode”).
 *      See CNSSI 4009-2015.
 */
contract DataDecoder {
    /**
     * @notice Decode a hex‐encoded string into raw bytes.
     * @param hexString The input string containing hex digits (0–9, a–f, A–F), even length.
     * @return result   The decoded bytes.
     */
    function decodeHex(string calldata hexString) external pure returns (bytes memory result) {
        bytes memory input = bytes(hexString);
        uint256 len = input.length;
        require(len % 2 == 0, "DataDecoder: hex length must be even");

        result = new bytes(len / 2);
        for (uint256 i = 0; i < len / 2; i++) {
            uint8 hi = _fromHexChar(input[2 * i]) << 4;
            uint8 lo = _fromHexChar(input[2 * i + 1]);
            result[i] = bytes1(hi | lo);
        }
    }

    /**
     * @dev Convert a single hex character to its numeric value.
     */
    function _fromHexChar(bytes1 c) internal pure returns (uint8) {
        uint8 char = uint8(c);

        // '0'–'9' → 0–9
        if (char >= 0x30 && char <= 0x39) {
            return char - 0x30;
        }
        // 'A'–'F' → 10–15
        if (char >= 0x41 && char <= 0x46) {
            return char - 0x41 + 10;
        }
        // 'a'–'f' → 10–15
        if (char >= 0x61 && char <= 0x66) {
            return char - 0x61 + 10;
        }
        revert("DataDecoder: invalid hex character");
    }
}
