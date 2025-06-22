// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract AESMessageSignatureVerifier {
    using ECDSA for bytes32;

    address public trustedSigner;

    event EncryptedMessageSubmitted(address indexed user, bytes32 messageHash);

    constructor(address _trustedSigner) {
        trustedSigner = _trustedSigner;
    }

    /**
     * @notice Submit the keccak256 hash of an AES-encrypted message with a valid signature.
     * @param messageHash The hash of the AES-encrypted message.
     * @param nonce A nonce to prevent replay attacks.
     * @param signature A signature from the trusted signer (off-chain backend).
     */
    function submitEncryptedMessage(
        bytes32 messageHash,
        uint256 nonce,
        bytes calldata signature
    ) public {
        // Reconstruct digest as if signed off-chain
        bytes32 digest = keccak256(abi.encodePacked(msg.sender, messageHash, nonce))
            .toEthSignedMessageHash();

        address recovered = digest.recover(signature);
        require(recovered == trustedSigner, "Invalid signature");

        emit EncryptedMessageSubmitted(msg.sender, messageHash);
    }
}
