// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AsymmetricSignatureVerifier - ECDSA signature verifier using asymmetric cryptography

contract AsymmetricSignatureVerifier {
    event SignatureVerified(address signer, bytes32 messageHash);

    /// @notice Verifies that `expectedSigner` signed `messageHash`
    function verify(
        address expectedSigner,
        bytes32 messageHash,
        bytes calldata signature
    ) external pure returns (bool) {
        bytes32 ethSignedHash = toEthSignedMessageHash(messageHash);
        address recovered = recover(ethSignedHash, signature);
        require(recovered == expectedSigner, "Signature invalid");
        emit SignatureVerified(recovered, messageHash);
        return true;
    }

    function toEthSignedMessageHash(bytes32 hash) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    function recover(bytes32 hash, bytes memory sig) public pure returns (address) {
        require(sig.length == 65, "Invalid signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return ecrecover(hash, v, r, s);
    }
}
