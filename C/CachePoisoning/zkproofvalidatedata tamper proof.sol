interface IZKVerifier {
    function verifyProof(bytes calldata proof) external view returns (bool);
}

contract ZKValidatedCache {
    IZKVerifier public verifier;
    bytes public cachedProof;

    constructor(address _verifier) {
        verifier = IZKVerifier(_verifier);
    }

    function cache(bytes calldata proof) external {
        require(verifier.verifyProof(proof), "ZK proof invalid");
        cachedProof = proof;
    }
}
