interface IZKVerifier {
    function verifyProof(bytes calldata proof) external view returns (bool);
}

contract ZKBridge {
    IZKVerifier public verifier;
    mapping(bytes32 => bool) public verifiedEvents;

    constructor(address _verifier) {
        verifier = IZKVerifier(_verifier);
    }

    function proveAndExecute(bytes calldata proof, bytes32 eventId) public {
        require(verifier.verifyProof(proof), "Invalid proof");
        require(!verifiedEvents[eventId], "Event already executed");
        verifiedEvents[eventId] = true;

        // Execute cross-chain action
    }
}
