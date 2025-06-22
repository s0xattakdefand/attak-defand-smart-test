interface IZKProof {
    function verify(bytes calldata zkProof, bytes32 pubInput) external view returns (bool);
}

contract zkAccessDetector {
    IZKProof public verifier;
    mapping(bytes32 => bool) public knownGoodIDs;

    constructor(address _verifier) {
        verifier = IZKProof(_verifier);
    }

    function register(bytes32 zkId) external {
        knownGoodIDs[zkId] = true;
    }

    function zkLogin(bytes calldata proof, bytes32 pubInput) external view returns (bool suspicious) {
        bool valid = verifier.verify(proof, pubInput);
        if (!valid) return true;
        if (!knownGoodIDs[pubInput]) return true; // not seen before
        return false; // ✅ normal behavior
    }
}
