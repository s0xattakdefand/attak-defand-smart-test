// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * OTHER TYPE:
 * A stub for a ZK-based contract, 
 * where an off-chain circuit proves a statement about a secret 
 * without revealing the secret on-chain.
 */
interface IZKVerifier {
    function verifyProof(bytes calldata proof) external view returns (bool);
}

contract ZKPrivacy {
    IZKVerifier public verifier;

    event ZKVerified(address indexed user);

    constructor(address _verifier) {
        verifier = IZKVerifier(_verifier);
    }

    /**
     * @dev Off-chain, you generate a zero-knowledge proof that you know some secret 
     * without revealing it. On-chain, we only store the proof result = true/false.
     */
    function proveSecret(bytes calldata proof) external {
        // The contract doesn't store your secret or even a hash, 
        // it just checks a ZK proof is valid
        bool valid = verifier.verifyProof(proof);
        require(valid, "Invalid ZK proof");
        
        emit ZKVerified(msg.sender);
    }
}
