// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ECDSA Signature Verification
 * @dev Complete ECDSA verification using Ethereum's ecrecover precompile (0x01).
 *      Supports eth_sign, personal_sign, and raw signatures.
 *      Includes utility functions for message hashing and signature splitting.
 * @author Grok
 */
contract ECDSA {
    // ecrecover precompile address
    address private constant ECRECOVER = address(0x01);

    /**
     * @dev Recovers the signer address from a signature (v, r, s)
     * @param hash The keccak256 hash of the message
     * @param v Recovery identifier (27 or 28 for eth_sign, 0 or 1 for raw)
     * @param r First 32 bytes of signature
     * @param s Second 32 bytes of signature
     * @return signer The address that produced the signature
     */
    function recover(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public view returns (address signer) {
        (bool success, bytes memory data) = ECRECOVER.staticcall(
            abi.encode(hash, v, r, s)
        );
        require(success, "ecrecover failed");
        return abi.decode(data, (address));
    }

    /**
     * @dev Recovers signer from raw signature (65 bytes: r || s || v)
     * @param hash Message hash
     * @param signature 65-byte signature
     * @return signer Recovered address
     */
    function recover(bytes32 hash, bytes memory signature) public view returns (address signer) {
        require(signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        if (v < 27) {
            v += 27;
        }

        return recover(hash, v, r, s);
    }

    /**
     * @dev Hashes a message like eth_sign: keccak256("\x19Ethereum Signed Message:\n32" + hash)
     * @param message Original message
     * @return hashedMessage Signed message hash
     */
    function hashMessage(bytes memory message) public pure returns (bytes32 hashedMessage) {
        bytes32 hash = keccak256(message);
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    /**
     * @dev Hashes a string message (for personal_sign)
     * @param message String message
     * @return hashedMessage Signed message hash
     */
    function hashMessage(string memory message) public pure returns (bytes32 hashedMessage) {
        return hashMessage(bytes(message));
    }

    /**
     * @dev Verifies that a signature is valid for a message and signer
     * @param message Original message
     * @param signature 65-byte signature
     * @param signer Expected signer address
     * @return isValid True if signature is valid
     */
    function verify(
        bytes memory message,
        bytes memory signature,
        address signer
    ) public view returns (bool isValid) {
        bytes32 msgHash = hashMessage(message);
        address recovered = recover(msgHash, signature);
        return recovered == signer;
    }

    /**
     * @dev Verifies string message
     * @param message String message
     * @param signature 65-byte signature
     * @param signer Expected signer
     * @return isValid True if valid
     */
    function verify(
        string memory message,
        bytes memory signature,
        address signer
    ) public view returns (bool isValid) {
        return verify(bytes(message), signature, signer);
    }

    /**
     * @dev Verifies raw hash (no prefix)
     * @param hash Message hash
     * @param signature 65-byte signature
     * @param signer Expected signer
     * @return isValid True if valid
     */
    function verifyRaw(
        bytes32 hash,
        bytes memory signature,
        address signer
    ) public view returns (bool isValid) {
        address recovered = recover(hash, signature);
        return recovered == signer;
    }

    /**
     * @dev Splits 65-byte signature into (r, s, v)
     * @param signature 65-byte signature
     * @return r The r component of the signature
     * @return s The s component of the signature
     * @return v The recovery byte (v)
     */
    function splitSignature(bytes memory signature)
        public
        pure
        returns (bytes32 r, bytes32 s, uint8 v)
    {
        require(signature.length == 65, "Invalid signature length");

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        if (v < 27) {
            v += 27;
        }

        return (r, s, v);
    }

    /**
     * @dev Checks if signature is low-s (prevents malleability)
     * @param s Signature s value
     * @return isLow True if s <= n/2
     */
    function isLowS(bytes32 s) public pure returns (bool isLow) {
        uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        return uint256(s) <= n / 2;
    }
}