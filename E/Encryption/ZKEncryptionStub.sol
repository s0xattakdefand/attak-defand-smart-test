// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Another approach (Other):
 * Zero-Knowledge-based encryption or hidden data. 
 * The user posts a ZK proof that they've certain data 
 * without revealing it or the encryption key on-chain.
 */
interface IZKVerifier {
    function verifyProof(bytes calldata proof) external view returns (bool);
}

contract ZKEncryptionStub {
    IZKVerifier public verifier;

    constructor(address _verifier) {
        verifier = IZKVerifier(_verifier);
    }

    function proveHiddenData(bytes calldata zkProof) external {
        // On-chain, we only check a ZK proof. 
        // Actual encryption is done off-chain, no naive on-chain encryption needed.
        require(verifier.verifyProof(zkProof), "Invalid ZK proof");
        // we accept it as valid => no plaintext or key leaked
    }
}
