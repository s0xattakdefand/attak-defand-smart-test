// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ECM - Elliptic Curve Multiplier
 * @dev Complete smart contract for performing scalar multiplication on secp256k1 curve.
 *      Uses Ethereum precompile ecMul (address 0x06) to compute Q = k × G.
 *      Includes public key generation, point validation, and batch operations.
 * @author Grok
 */
contract ECM {
    // secp256k1 curve parameters
    uint256 public constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 public constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    uint256 public constant P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 public constant N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    event PublicKeyComputed(uint256 indexed scalar, uint256 x, uint256 y);
    event BatchMultiplication(uint256 count);

    /**
     * @dev Compute public key: Q = k × G using ecMul precompile
     * @param k Private key scalar (must be 1 <= k < N)
     * @return x X coordinate of public key
     * @return y Y coordinate of public key
     */
    function multiply(uint256 k) public returns (uint256 x, uint256 y) {
        require(k > 0 && k < N, "Invalid scalar: must be in [1, N-1]");

        (bool success, bytes memory data) = 
            address(0x06).staticcall(abi.encode(k, GX, GY));
        require(success, "ecMul precompile failed");

        (x, y) = abi.decode(data, (uint256, uint256));
        emit PublicKeyComputed(k, x, y);
        return (x, y);
    }

    /**
     * @dev Batch multiply: compute Q_i = k_i × G for multiple scalars
     * @param scalars Array of private key scalars
     * @return xs Array of X coordinates
     * @return ys Array of Y coordinates
     */
    function batchMultiply(uint256[] memory scalars) 
        public 
        returns (uint256[] memory xs, uint256[] memory ys) 
    {
        require(scalars.length > 0, "Empty scalars array");
        require(scalars.length <= 100, "Too many scalars (max 100)");

        xs = new uint256[](scalars.length);
        ys = new uint256[](scalars.length);

        for (uint256 i = 0; i < scalars.length; i++) {
            require(scalars[i] > 0 && scalars[i] < N, "Invalid scalar");
            (xs[i], ys[i]) = multiply(scalars[i]);
        }

        emit BatchMultiplication(scalars.length);
        return (xs, ys);
    }

    /**
     * @dev Validate that a point (x, y) lies on secp256k1 curve: y² = x³ + 7
     * @param x X coordinate
     * @param y Y coordinate
     * @return isValid True if point is on curve
     */
    function isOnCurve(uint256 x, uint256 y) public pure returns (bool isValid) {
        if (x >= P || y >= P) return false;
        uint256 y2 = mulmod(y, y, P);
        uint256 x3 = mulmod(mulmod(x, x, P), x, P);
        return (x3 + 7) % P == y2;
    }

    /**
     * @dev Validate public key from multiply() result
     * @param k Scalar used
     * @return x X coordinate
     * @return y Y coordinate
     * @return valid True if on curve
     */
    function multiplyAndValidate(uint256 k) 
        public 
        returns (uint256 x, uint256 y, bool valid) 
    {
        (x, y) = multiply(k);
        valid = isOnCurve(x, y);
        return (x, y, valid);
    }

    /**
     * @dev Compute compressed public key: 0x02/0x03 + x (33 bytes)
     * @param x X coordinate
     * @param y Y coordinate
     * @return compressed 33-byte compressed key
     */
    function compressKey(uint256 x, uint256 y) public pure returns (bytes memory) {
        bytes memory key = new bytes(33);
        key[0] = (y % 2 == 0) ? bytes1(0x02) : bytes1(0x03);
        for (uint256 i = 0; i < 32; i++) {
            key[32 - i] = bytes1(uint8(x >> (i * 8)));
        }
        return key;
    }

    /**
     * @dev Compute uncompressed public key: 0x04 + x + y (65 bytes)
     * @param x X coordinate
     * @param y Y coordinate
     * @return uncompressed 65-byte uncompressed key
     */
    function uncompressKey(uint256 x, uint256 y) public pure returns (bytes memory) {
        bytes memory key = new bytes(65);
        key[0] = 0x04;
        for (uint256 i = 0; i < 32; i++) {
            key[32 - i] = bytes1(uint8(x >> (i * 8)));
            key[64 - i] = bytes1(uint8(y >> (i * 8)));
        }
        return key;
    }

    /**
     * @dev Generate public key and return in both formats
     * @param k Private key scalar
     * @return x X coordinate
     * @return y Y coordinate
     * @return compressed 33-byte compressed key
     * @return uncompressed 65-byte uncompressed key
     */
    function generateKey(uint256 k) 
        public 
        returns (
            uint256 x,
            uint256 y,
            bytes memory compressed,
            bytes memory uncompressed
        ) 
    {
        (x, y) = multiply(k);
        compressed = compressKey(x, y);
        uncompressed = uncompressKey(x, y);
        return (x, y, compressed, uncompressed);
    }
}