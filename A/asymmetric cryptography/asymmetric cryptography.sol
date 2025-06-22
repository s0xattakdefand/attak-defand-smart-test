// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AsymmetricVerifier - Basic ECDSA asymmetric cryptography verification

contract AsymmetricVerifier {
    event Verified(address signer, bytes32 messageHash);

    /// @notice Verifies ECDSA signature over a given message hash
    function verifySignature(
        bytes32 messageHash,
        bytes calldata signature,
        address expectedSigner
    ) external pure returns (bool) {
        bytes32 ethSigned = toEthSignedMessageHash(messageHash);
        address recovered = recoverSigner(ethSigned, signature);
        require(recovered == expectedSigner, "Invalid signature");
        return true;
    }

    function toEthSignedMessageHash(bytes32 hash) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    function recoverSigner(bytes32 hash, bytes memory sig) public pure returns (address) {
        require(sig.length == 65, "Invalid sig length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }
        return ecrecover(hash, v, r, s);
    }
}
