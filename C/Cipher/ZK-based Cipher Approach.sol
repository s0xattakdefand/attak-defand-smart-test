interface IZKCipherVerifier {
    function verifyProof(bytes calldata proof) external view returns (bool);
}

contract ZKCipher {
    IZKCipherVerifier public verifier;

    constructor(address _verifier) {
        verifier = IZKCipherVerifier(_verifier);
    }

    function verifyEncryptedData(bytes calldata zkProof) external view returns (bool) {
        // Off-chain encrypted data + ZK proof that it's valid
        // On-chain we only confirm the ZK proof is correct
        return verifier.verifyProof(zkProof);
    }
}
