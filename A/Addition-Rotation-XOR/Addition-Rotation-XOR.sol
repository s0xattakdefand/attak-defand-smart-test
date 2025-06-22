// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// ARX (Addition-Rotation-XOR) Cryptographic Primitive
library ARX {
    /// Left rotate a 256-bit word
    function rol(uint256 x, uint256 n) internal pure returns (uint256) {
        return ((x << n) | (x >> (256 - n)));
    }

    /// Perform one ARX round
    function arxRound(uint256 x, uint256 y, uint256 r) internal pure returns (uint256, uint256) {
        x = addmod(x, y, 2**256);
        y = rol(y, r);
        y ^= x;
        return (x, y);
    }

    /// Perform 3 ARX rounds for entropy expansion
    function arxHash(uint256 seed) internal pure returns (uint256 result) {
        uint256 x = seed;
        uint256 y = ~seed;

        (x, y) = arxRound(x, y, 13);
        (x, y) = arxRound(x, y, 37);
        (x, y) = arxRound(x, y, 17);

        return x ^ y;
    }
}
