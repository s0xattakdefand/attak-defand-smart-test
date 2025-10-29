// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ECDH Key Agreement Contract
 * @dev Full ECDH implementation using Ethereum precompiles (ecMul at 0x06).
 *      Uses secp256k1 curve (same as Bitcoin/Ethereum).
 *      For demo, testing, or ZK proof integration.
 * @author Grok
 */
contract ECDH {
    // secp256k1 curve parameters
    uint256 public constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 public constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    uint256 public constant P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 public constant N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    event PublicKey(uint256 x, uint256 y);
    event SharedSecret(uint256 x, uint256 y);
    event ECDHSuccess(uint256 sharedX);

    /**
     * @dev Compute public key: Q = priv * G
     * @param privKey Private key scalar
     * @return x The X coordinate of the public key point
     * @return y The Y coordinate of the public key point
     */
    function getPublicKey(uint256 privKey) public returns (uint256 x, uint256 y) {
        require(privKey > 0 && privKey < N, "Invalid private key");

        (bool success, bytes memory data) = 
            address(0x06).staticcall(abi.encode(privKey, GX, GY));
        require(success, "ecMul failed");

        (x, y) = abi.decode(data, (uint256, uint256));
        emit PublicKey(x, y);
        return (x, y);
    }

    /**
     * @dev Compute shared secret: S = privA * pubB
     * @param privA Private key of party A
     * @param pubBx Public key X coordinate of party B
     * @param pubBy Public key Y coordinate of party B
     * @return x The X coordinate of the shared secret point
     * @return y The Y coordinate of the shared secret point
     */
    function computeSharedSecret(
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
        emit SharedSecret(x, y);
        return (x, y);
    }

    /**
     * @dev Full ECDH demo: Alice and Bob compute same secret
     *      WARNING: For testing only! Never use real keys on-chain.
     * @param alicePriv Alice's private key
     * @param bobPriv Bob's private key
     * @return success Whether the shared secrets match
     * @return sharedX The X coordinate of the shared secret
     */
    function runECDHDemo(
        uint256 alicePriv,
        uint256 bobPriv
    ) public returns (bool success, uint256 sharedX) {
        require(alicePriv > 0 && alicePriv < N, "Alice: invalid key");
        require(bobPriv > 0 && bobPriv < N, "Bob: invalid key");

        // Compute public keys
        (uint256 alicePubX, uint256 alicePubY) = getPublicKey(alicePriv);
        (uint256 bobPubX,   uint256 bobPubY)   = getPublicKey(bobPriv);

        // Compute shared secrets
        (uint256 aliceSharedX, ) = computeSharedSecret(alicePriv, bobPubX, bobPubY);
        (uint256 bobSharedX,   ) = computeSharedSecret(bobPriv,   alicePubX, alicePubY);

        // Verify match
        success = (aliceSharedX == bobSharedX);
        sharedX = aliceSharedX;

        if (success) {
            emit ECDHSuccess(sharedX);
        } else {
            revert("ECDH failed: secrets do not match");
        }

        return (true, sharedX);
    }

    /**
     * @dev Derive 32-byte symmetric key from shared point X coordinate
     * @param sharedX X coordinate of the shared secret point
     * @return key 32-byte symmetric key (e.g., for AES-256)
     */
    function deriveSymmetricKey(uint256 sharedX) public pure returns (bytes32 key) {
        return keccak256(abi.encodePacked(sharedX));
    }

    /**
     * @dev Validate that a point (x, y) is on the secp256k1 curve: y^2 = x^3 + 7
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
}