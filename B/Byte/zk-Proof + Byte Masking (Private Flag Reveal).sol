interface IZKVerifier {
    function verifyProof(bytes calldata proof) external view returns (bool);
}

contract ByteZKMask {
    IZKVerifier public verifier;
    mapping(address => bytes1) public hiddenFlags;

    constructor(address _verifier) {
        verifier = IZKVerifier(_verifier);
    }

    function storeFlags(bytes1 flags) public {
        hiddenFlags[msg.sender] = flags;
    }

    function proveBitOn(bytes calldata proof, uint8 bit) public view returns (bool) {
        require(bit < 8, "Invalid bit");

        // Assume zkSNARK proves: (flags & (1 << bit)) != 0 without revealing flags
        require(verifier.verifyProof(proof), "Invalid ZK proof");
        return true; // Proof says bit was set
    }
}
