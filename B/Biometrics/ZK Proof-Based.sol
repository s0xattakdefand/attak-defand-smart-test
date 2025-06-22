// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IZKVerifier {
    function verifyProof(bytes calldata proof) external view returns (bool);
}

contract ZKBiometricVerification {
    mapping(address => bool) public isVerified;
    IZKVerifier public verifier;
    address public admin;

    event BiometricVerified(address indexed user);

    constructor(address _verifier) {
        verifier = IZKVerifier(_verifier);
        admin = msg.sender;
    }

    /**
     * @notice Verifies a ZK proof and binds the result to the sender's address.
     * @param proof The zero-knowledge proof (format depends on verifier).
     */
    function verifyZKProof(bytes calldata proof) public {
        require(verifier.verifyProof(proof), "Invalid ZK proof");
        isVerified[msg.sender] = true;

        emit BiometricVerified(msg.sender);
    }

    /**
     * @notice Check if a user has been verified via ZK.
     */
    function checkVerified(address user) public view returns (bool) {
        return isVerified[user];
    }
}
