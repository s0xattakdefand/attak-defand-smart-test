interface IZKVerifier {
    function verifyProof(bytes calldata proof) external view returns (bool);
}

contract ZKProofCloud {
    IZKVerifier public verifier;

    function setVerifier(address v) external {
        // admin
        verifier = IZKVerifier(v);
    }

    function acceptProof(bytes calldata proof) external view returns (bool) {
        return verifier.verifyProof(proof);
    }
}
