// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ECDHVerify {
    // secp256k1 base point G
    uint256 constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    uint256 constant P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    // Compute public key: Q = d * G
    function publicKey(uint256 privKey) public view returns (uint256 x, uint256 y) {
        (bool success, bytes memory data) = 
            address(0x06).staticcall(abi.encode(privKey, GX, GY)); // ecMul
        require(success, "ecMul failed");
        (x, y) = abi.decode(data, (uint256, uint256));
    }

    // Compute shared point: S = privA * pubB
    function sharedSecret(
        uint256 privA,
        uint256 pubBx,
        uint256 pubBy
    ) public view returns (uint256 x, uint256 y) {
        (bool success, bytes memory data) = 
            address(0x06).staticcall(abi.encode(privA, pubBx, pubBy));
        require(success, "ecMul failed");
        (x, y) = abi.decode(data, (uint256, uint256));
    }

    // Example: Alice proves she knows dₐ such that dₐ * Bob's pub = shared
    function verifySharedSecret(
        uint256 alicePriv,       // only for demo — NEVER in prod
        uint256 bobPubX,
        uint256 bobPubY,
        uint256 expectedX
    ) public view returns (bool) {
        (uint256 sx, ) = sharedSecret(alicePriv, bobPubX, bobPubY);
        return sx == expectedX;
    }
}