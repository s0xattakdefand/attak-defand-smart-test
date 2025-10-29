// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ECMP - Elliptic Curve Multi-Point Operations
 * @dev Complete smart contract for secp256k1 multi-point scalar multiplication and point addition.
 *      Uses Ethereum precompiles:
 *        - ecMul (0x06): Q = k × P
 *        - ecAdd (0x07): R = P + Q
 *      Includes batch operations, point validation, key aggregation, and MSM.
 *      Fixed: Replaced `mensmod` (typo) with `mulmod`
 * @author Grok
 */
contract ECMP {
    // secp256k1 curve parameters
    uint256 public constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 public constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    uint256 public constant P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 public constant N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    event PointMultiplied(uint256 indexed scalar, uint256 x, uint256 y);
    event PointsAdded(uint256 x1, uint256 y1, uint256 x2, uint256 y2, uint256 rx, uint256 ry);
    event BatchMultiplied(uint256 count);
    event KeyAggregated(uint256 aggX, uint256 aggY);

    /**
     * @dev Scalar multiply: Q = k × P using ecMul precompile
     * @param k Scalar (private key)
     * @param px X coordinate of point P
     * @param py Y coordinate of point P
     * @return qx X coordinate of result Q
     * @return qy Y coordinate of result Q
     */
    function ecMul(uint256 k, uint256 px, uint256 py) public returns (uint256 qx, uint256 qy) {
        require(k > 0 && k < N, "Invalid scalar");
        require(px < P && py < P, "Point out of range");

        (bool success, bytes memory data) = 
            address(0x06).staticcall(abi.encode(k, px, py));
        require(success, "ecMul failed");

        (qx, qy) = abi.decode(data, (uint256, uint256));
        emit PointMultiplied(k, qx, qy);
        return (qx, qy);
    }

    /**
     * @dev Point addition: R = P + Q using ecAdd precompile
     * @param px X of P
     * @param py Y of P
     * @param qx X of Q
     * @param qy Y of Q
     * @return rx X of R
     * @return ry Y of R
     */
    function ecAdd(
        uint256 px, uint256 py,
        uint256 qx, uint256 qy
    ) public returns (uint256 rx, uint256 ry) {
        require(px < P && py < P && qx < P && qy < P, "Points out of range");

        (bool success, bytes memory data) = 
            address(0x07).staticcall(abi.encode(px, py, qx, qy));
        require(success, "ecAdd failed");

        (rx, ry) = abi.decode(data, (uint256, uint256));
        emit PointsAdded(px, py, qx, qy, rx, ry);
        return (rx, ry);
    }

    /**
     * @dev Generate public key from private key: Q = k × G
     * @param k Private key
     * @return x X coordinate
     * @return y Y coordinate
     */
    function publicKey(uint256 k) public returns (uint256 x, uint256 y) {
        return ecMul(k, GX, GY);
    }

    /**
     * @dev Batch scalar multiplication: Q_i = k_i × G
     * @param scalars Array of private keys
     * @return xs Array of X coordinates
     * @return ys Array of Y coordinates
     */
    function batchPublicKeys(uint256[] memory scalars) 
        public 
        returns (uint256[] memory xs, uint256[] memory ys) 
    {
        require(scalars.length > 0 && scalars.length <= 50, "Invalid batch size");

        xs = new uint256[](scalars.length);
        ys = new uint256[](scalars.length);

        for (uint256 i = 0; i < scalars.length; i++) {
            (xs[i], ys[i]) = publicKey(scalars[i]);
        }

        emit BatchMultiplied(scalars.length);
        return (xs, ys);
    }

    /**
     * @dev Aggregate multiple public keys: R = Q1 + Q2 + ... + Qn
     * @param pubXs Array of X coordinates
     * @param pubYs Array of Y coordinates
     * @return aggX Aggregated X
     * @return aggY Aggregated Y
     */
    function aggregateKeys(
        uint256[] memory pubXs,
        uint256[] memory pubYs
    ) public returns (uint256 aggX, uint256 aggY) {
        require(pubXs.length == pubYs.length && pubXs.length > 0, "Invalid input");
        require(pubXs.length <= 50, "Too many keys");

        (aggX, aggY) = (pubXs[0], pubYs[0]);

        for (uint256 i = 1; i < pubXs.length; i++) {
            (aggX, aggY) = ecAdd(aggX, aggY, pubXs[i], pubYs[i]);
        }

        emit KeyAggregated(aggX, aggY);
        return (aggX, aggY);
    }

    /**
     * @dev Multi-scalar multiplication: R = k1×P1 + k2×P2 + ... + kn×Pn
     * @param scalars Array of scalars k_i
     * @param pointsX Array of P_i.X
     * @param pointsY Array of P_i.Y
     * @return rx Result X
     * @return ry Result Y
     */
    function multiScalarMul(
        uint256[] memory scalars,
        uint256[] memory pointsX,
        uint256[] memory pointsY
    ) public returns (uint256 rx, uint256 ry) {
        require(
            scalars.length == pointsX.length && 
            scalars.length == pointsY.length && 
            scalars.length > 0 && 
            scalars.length <= 20,
            "Invalid input"
        );

        // Start with first term: k0 × P0
        (rx, ry) = ecMul(scalars[0], pointsX[0], pointsY[0]);

        // Add remaining terms
        for (uint256 i = 1; i < scalars.length; i++) {
            uint256 qx;
            uint256 qy;
            (qx, qy) = ecMul(scalars[i], pointsX[i], pointsY[i]);
            (rx, ry) = ecAdd(rx, ry, qx, qy);
        }

        return (rx, ry);
    }

    /**
     * @dev Validate point is on secp256k1 curve: y² = x³ + 7
     * @param x X coordinate
     * @param y Y coordinate
     * @return isValid True if on curve
     */
    function isOnCurve(uint256 x, uint256 y) public pure returns (bool isValid) {
        if (x >= P || y >= P) return false;
        uint256 y2 = mulmod(y, y, P);
        uint256 x3 = mulmod(mulmod(x, x, P), x, P);  // Fixed: mensmod → mulmod
        return (x3 + 7) % P == y2;
    }

    /**
     * @dev Validate and multiply: Q = k × P with curve check
     * @param k Scalar
     * @param px P.X
     * @param py P.Y
     * @return qx Q.X
     * @return qy Q.Y
     * @return valid True if Q on curve
     */
    function safeEcMul(uint256 k, uint256 px, uint256 py) 
        public 
        returns (uint256 qx, uint256 qy, bool valid) 
    {
        require(isOnCurve(px, py), "Input point not on curve");
        (qx, qy) = ecMul(k, px, py);
        valid = isOnCurve(qx, qy);
        return (qx, qy, valid);
    }

    /**
     * @dev Compress public key: 0x02/0x03 + X
     * @param x X coordinate
     * @param y Y coordinate
     * @return compressed 33-byte key
     */
    function compress(uint256 x, uint256 y) public pure returns (bytes memory) {
        bytes memory key = new bytes(33);
        key[0] = (y % 2 == 0) ? bytes1(0x02) : bytes1(0x03);
        for (uint256 i = 0; i < 32; i++) {
            key[32 - i] = bytes1(uint8(x >> (i * 8)));
        }
        return key;
    }
}