// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AffineTransform — Linear + translation mapping for zk circuits, ECC, AES prep
contract AffineTransform {
    uint256 public A; // Multiplier
    uint256 public B; // Translation

    event AffineApplied(uint256 indexed input, uint256 output);

    constructor(uint256 _A, uint256 _B) {
        A = _A;
        B = _B;
    }

    function apply(uint256 x) external view returns (uint256 y) {
        unchecked {
            return A * x + B;
        }
    }

    function applyAndLog(uint256 x) external returns (uint256 y) {
        unchecked {
            y = A * x + B;
            emit AffineApplied(x, y);
        }
    }

    function getConstants() external view returns (uint256, uint256) {
        return (A, B);
    }
}
