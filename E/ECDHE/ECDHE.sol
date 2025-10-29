// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ECDHE Ephemeral Key Exchange
 * @dev Full ECDHE using Ethereum precompiles (ecMul at 0x06).
 *      Demonstrates Perfect Forward Secrecy (PFS).
 *      For testing, ZK proofs, or off-chain coordination.
 * @author Grok
 */
contract ECDHE {
    // secp256k1 curve parameters
    uint256 public constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 public constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    uint256 public constant P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 public constant N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    event EphemeralPublicKey(uint256 indexed party, uint256 x, uint256 y);
    event EphemeralSharedSecret(uint256 x, uint256 y);
    event ECDHESuccess(uint256 sharedX, uint256 sessionId);

    /**
     * @dev Generate ephemeral public key: Q = priv * G
     * @param privKey Ephemeral private key
     * @return x X coordinate
     * @return y Y coordinate
     */
    function generateEphemeralKey(uint256 privKey) public returns (uint256 x, uint256 y) {
        require(privKey > 0 && privKey < N, "Invalid ephemeral private key");

        (bool success, bytes memory data) = 
            address(0x06).staticcall(abi.encode(privKey, GX, GY));
        require(success, "ecMul failed");

        (x, y) = abi.decode(data, (uint256, uint256));
        emit EphemeralPublicKey(uint256(uint160(msg.sender)), x, y);
        return (x, y);
    }

    /**
     * @dev Compute ephemeral shared secret: S = privA * pubB
     * @param privA Ephemeral private key of party A
     * @param pubBx Ephemeral public key X of party B
     * @param pubBy Ephemeral public key Y of party B
     * @return x X coordinate of shared point
     * @return y Y coordinate of shared point
     */
    function computeEphemeralSecret(
        uint256 privA,
        uint256 pubBx,
        uint256 pubBy
    ) public returns (uint256 x, uint256 y) {
        require(privA > 0 && privA < N, "Invalid private key");
        require(pubBx < P && pubBy < P, "Public key out of range");

        (bool success, bytes memory data) = 
            address(0x06).staticcall(abi.encode(privA, pubBx, pubBy));
        require(success, "ecMul failed");

        (x, y) = abi.decode(data, (uint256, uint256));
        emit EphemeralSharedSecret(x, y);
        return (x, y);
    }

    /**
     * @dev Full ECDHE session demo
     *      Alice and Bob generate ephemeral keys and agree on shared secret
     *      WARNING: For testing only! Real ECDHE is off-chain.
     * @param alicePriv Alice's ephemeral private key
     * @param bobPriv Bob's ephemeral private key
     * @return success True if secrets match
     * @return sharedX X coordinate of shared secret
     * @return sessionId Unique session identifier
     */
    function runECDHESession(
        uint256 alicePriv,
        uint256 bobPriv
    ) public returns (bool success, uint256 sharedX, uint256 sessionId) {
        require(alicePriv > 0 && alicePriv < N, "Alice: invalid ephemeral key");
        require(bobPriv > 0 && bobPriv < N, "Bob: invalid ephemeral key");

        // Generate ephemeral public keys
        (uint256 alicePubX, uint256 alicePubY) = generateEphemeralKey(alicePriv);
        (uint256 bobPubX,   uint256 bobPubY)   = generateEphemeralKey(bobPriv);

        // Compute shared secrets
        (uint256 aliceSharedX, ) = computeEphemeralSecret(alicePriv, bobPubX, bobPubY);
        (uint256 bobSharedX,   ) = computeEphemeralSecret(bobPriv,   alicePubX, alicePubY);

        // Verify match
        success = (aliceSharedX == bobSharedX);
        sharedX = aliceSharedX;
        sessionId = uint256(keccak256(abi.encodePacked(block.timestamp, alicePubX, bobPubX)));

        if (success) {
            emit ECDHESuccess(sharedX, sessionId);
        } else {
            revert("ECDHE failed: shared secrets do not match");
        }

        return (true, sharedX, sessionId);
    }

    /**
     * @dev Derive session key from shared secret (HKDF-like)
     * @param sharedX X coordinate of shared point
     * @param info Context-specific info (e.g., "tls13")
     * @return key 32-byte session key
     */
    function deriveSessionKey(
        uint256 sharedX,
        bytes memory info
    ) public pure returns (bytes32 key) {
        return keccak256(abi.encodePacked(sharedX, info));
    }

    /**
     * @dev Validate point is on secp256k1: y^2 = x^3 + 7
     * @param x X coordinate
     * @param y Y coordinate
     * @return isValid True if on curve
     */
    function validatePoint(uint256 x, uint256 y) public pure returns (bool isValid) {
        if (x >= P || y >= P) return false;
        uint256 y2 = mulmod(y, y, P);
        uint256 x3 = mulmod(mulmod(x, x, P), x, P);
        return (x3 + 7) % P == y2;
    }
}