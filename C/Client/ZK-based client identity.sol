interface IZKClientVerifier {
    function verifyProof(bytes calldata proof) external view returns (bool);
}

contract ZKClient {
    IZKClientVerifier public verifier;
    event VerifiedAction(address user);

    constructor(address _verifier) {
        verifier = IZKClientVerifier(_verifier);
    }

    function doAction(bytes calldata proof) external {
        require(verifier.verifyProof(proof), "Invalid ZK proof");
        emit VerifiedAction(msg.sender);
    }
}
