interface IzkVerifier {
    function verifyProof(bytes calldata proof, bytes32 traitHash) external view returns (bool);
}

contract zkIDVerifier {
    address public zkVerifier;

    function checkTrait(bytes calldata proof, bytes32 traitHash) external view returns (bool) {
        return IzkVerifier(zkVerifier).verifyProof(proof, traitHash);
    }
}
