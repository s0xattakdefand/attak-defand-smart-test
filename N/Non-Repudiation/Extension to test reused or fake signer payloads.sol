interface ISignatureVerifier {
    function verify(address expectedSigner, bytes32 hash, bytes calldata sig) external pure returns (bool);
}

contract AutoSimWithReplayCheck {
    ISignatureVerifier public verifier;
    mapping(bytes32 => bool) public usedHashes;

    constructor(address _verifier) {
        verifier = ISignatureVerifier(_verifier);
    }

    function simulateAction(bytes32 hash, bytes calldata sig, address expectedSigner) external {
        require(!usedHashes[hash], "Replay detected");
        bool ok = verifier.verify(expectedSigner, hash, sig);
        require(ok, "Invalid signature");
        usedHashes[hash] = true;
    }
}
