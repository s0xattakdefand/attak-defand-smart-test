// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract DefendEncryptionVerifier {
    using ECDSA for bytes32;

    address public trustedSigner;
    mapping(address => bytes32) public userEncryptedHash;
    mapping(address => uint256) public usedNonce;

    event EncryptedHashSubmitted(address indexed user, bytes32 messageHash, uint256 nonce);

    constructor(address _trustedSigner) {
        trustedSigner = _trustedSigner;
    }

    /**
     * @notice Verifies off-chain AES-encrypted message hash with backend signature.
     * @param messageHash The keccak256 hash of the encrypted message.
     * @param nonce A nonce to prevent replay attacks.
     * @param signature Signature from trusted signer for (user, hash, nonce).
     */
    function submitEncryptedMessage(
        bytes32 messageHash,
        uint256 nonce,
        bytes calldata signature
    ) public {
        require(nonce > usedNonce[msg.sender], "Nonce must increase");

        // Create the digest and sign it properly
        bytes32 digest = keccak256(abi.encodePacked(msg.sender, messageHash, nonce))
            .toEthSignedMessageHash(); // ✅ This works now

        address recovered = digest.recover(signature);
        require(recovered == trustedSigner, "Invalid signature");

        userEncryptedHash[msg.sender] = messageHash;
        usedNonce[msg.sender] = nonce;

        emit EncryptedHashSubmitted(msg.sender, messageHash, nonce);
    }

    function getMyEncryptedHash() public view returns (bytes32) {
        return userEncryptedHash[msg.sender];
    }
}
