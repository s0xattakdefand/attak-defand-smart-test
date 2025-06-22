interface IZKProofVerifier {
    function verify(bytes calldata proof, bytes32 signal) external view returns (bool);
}

contract ZKCommitmentVerifier {
    IZKProofVerifier public verifier;

    constructor(address _v) {
        verifier = IZKProofVerifier(_v);
    }

    function verifyCommitment(bytes calldata proof, bytes32 actionHash) external view returns (bool) {
        return verifier.verify(proof, actionHash);
    }
}
