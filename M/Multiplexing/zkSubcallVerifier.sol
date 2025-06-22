interface IZKVerifier {
    function verify(bytes calldata zkProof, bytes32 input) external view returns (bool);
}

contract zkWhitelistedMultiplexer {
    IZKVerifier public verifier;

    constructor(address _verifier) {
        verifier = IZKVerifier(_verifier);
    }

    function zkExecuteBatch(
        address[] calldata targets,
        bytes[] calldata payloads,
        bytes[] calldata zkProofs,
        bytes32[] calldata inputs
    ) external {
        require(targets.length == zkProofs.length, "Length mismatch");

        for (uint256 i = 0; i < targets.length; i++) {
            require(verifier.verify(zkProofs[i], inputs[i]), "ZK validation failed");
            (bool ok, ) = targets[i].call(payloads[i]);
            require(ok, "ZK call failed");
        }
    }
}
