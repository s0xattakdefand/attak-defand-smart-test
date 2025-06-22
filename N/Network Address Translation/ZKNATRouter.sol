interface IZKVerifier {
    function verify(bytes calldata proof, bytes32 input) external view returns (bool);
}

contract ZKNATRouter {
    IZKVerifier public verifier;

    function relayWithZK(
        address target,
        bytes calldata payload,
        bytes calldata proof,
        bytes32 aliasCommit
    ) external {
        require(verifier.verify(proof, aliasCommit), "Invalid zk alias proof");
        (bool ok, ) = target.call(payload);
        require(ok, "ZK NAT relay failed");
    }
}
