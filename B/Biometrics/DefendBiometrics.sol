// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract DefendBiometrics {
    using ECDSA for bytes32; // ✅ this enables extension methods for bytes32

    address public biometricSigner;
    mapping(address => bool) public isVerifiedBiometric;
    mapping(address => uint256) public latestNonce;

    event BiometricVerified(address indexed user);

    constructor(address _signer) {
        biometricSigner = _signer;
    }

    /**
     * @notice Verify biometric identity via a signature from a trusted biometric backend.
     * @param nonce A unique nonce for replay protection.
     * @param signature Signature of keccak256(user, nonce) signed by biometric backend.
     */
    function verifyBiometric(uint256 nonce, bytes calldata signature) public {
        require(!isVerifiedBiometric[msg.sender], "Already verified");
        require(nonce > latestNonce[msg.sender], "Nonce too low");

        bytes32 rawHash = keccak256(abi.encodePacked(msg.sender, nonce));
        
        // ✅ Use the extension method on bytes32 (correct usage!)
        bytes32 ethSignedMessageHash = rawHash.toEthSignedMessageHash();

        address recovered = ethSignedMessageHash.recover(signature);
        require(recovered == biometricSigner, "Invalid signature");

        isVerifiedBiometric[msg.sender] = true;
        latestNonce[msg.sender] = nonce;

        emit BiometricVerified(msg.sender);
    }

    function isVerified(address user) public view returns (bool) {
        return isVerifiedBiometric[user];
    }
}
